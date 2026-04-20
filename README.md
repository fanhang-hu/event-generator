forked https://github.com/falcosecurity/event-generator

And we only focus on syscall attacks. Here are 68 kinds of syscall attacks like ```syscall.AddingSshKeysToAuthorizedKeys``` etc, we found that 45 kinds of syscall attacks are ```withdisabled()```, therefore, we can't use falco to monitor it and we also can't use sysdig to moniter them. After checking, we find that only 8 kinds of attacks can be monitored and checked by sysdig, and my work need to promise sysdig can monitor the attacks.

Here are the 8 kinds of attacks, these attacks can use ```sysdig -r``` to filter.
```
syscall.DebugfsLaunchedInPrivilegedContainer
syscall.DisallowedSSHConnectionNonStandardPort
syscall.ExecutionFromDevShm
syscall.FilelessExecutionViaMemfdCreate
syscall.MountLaunchedInPrivilegedContainer
syscall.NetcatRemoteCodeExecutionInContainer
syscall.RunShellUntrusted
syscall.SystemUserInteractive
```

```bash
git clone https://github.com/falcosecurity/event-generator.git
cd event-generator
mkdir -p sysdig_scap
```

First, I start sysdig in terminal A,
```bash
cd sysdig_scap
sudo sysdig -w debugfs.scap
```

In terminal B, I use the following commands to start attacks in the docker,
```bash
# syscall.\specific attack\
sudo docker run -it --rm --privileged -v /var/run/docker.sock:/var/run/docker.sock -v /dev:/dev -v /etc:/etc_host falcosecurity/event-generator run syscall.DebugfsLaunchedInPrivilegedContainer
# I can also use --loop to keep running attacks, or --sleep
```

When we get .scap files, we can use falco to replay them, and identify the levels, like CRITICAL, WARNING and NOTICE,
```bash
sudo docker run --rm -it \
    --name falco \
    -v /home/hfh/event-generator/sysdig_scap/debugfs.scap:/capture.scap:ro \
    falcosecurity/falco:0.43.0 \
    falco -o engine.kind=replay -o engine.replay.capture_file=/capture.scap \
    2>&1 | sudo tee /home/hfh/event-generator/sysdig_scap/falco_replay/debugfs.log
```

What's more, we need to pre-process before giving to nodlink,
```bash
cd sysdig_scap
SCAP=debugfs.scap
USV=./scap2json/debugfs.usv
JSONL=./scap2json/debugfs.jsonl
JSON=./scap2json/debugfs.json
DELIM=$'\x1f'
FMT="%evt.args${DELIM}%evt.num${DELIM}%evt.rawtime${DELIM}%evt.type${DELIM}%fd.name${DELIM}%proc.cmdline${DELIM}%proc.name${DELIM}%proc.pcmdline${DELIM}%proc.pname"
sysdig -r "$SCAP" -p "$FMT" > "$USV"
jq -Rc '
split("\u001f") as $f |
{
  "evt.args": ($f[0] // ""),
  "evt.num": (($f[1] // "") | tonumber? // null),
  "evt.time": (($f[2] // "") | tonumber? // null),
  "evt.type": ($f[3] // ""),
  "fd.name": ($f[4] // ""),
  "proc.cmdline": ($f[5] // ""),
  "proc.name": ($f[6] // ""),
  "proc.pcmdline": ($f[7] // ""),
  "proc.pname": ($f[8] // "")
}
' "$USV" > "$JSONL"

cd scap2json
jq -s '.' "$JSONL" > "$JSON"
jq -c '.[]' debugfs.json > debugfs-v1.json

mkdir -p debugfs
sudo chown syssecure:syssecure ./
cd ..

grep '"proc.cmdline"' debugfs.json | sort -u | sed 's/^.*proc.cmdline": //' > debugfs.txt

sudo cp debugfs-v1.json /home/hfh/A-SysArmor/Nodlink/Sysdig/model/
sudo mv debugfs.* debugfs-v1.json debugfs
```

Now, use nodlink to detect,
```bash
cd /home/hfh/A-SysArmor/Nodlink/Sysdig/real-time
# 80th
python3 main.py --d /home/hfh/A-SysArmor/Nodlink/Sysdig/model --t 28.01 --f /home/hfh/A-SysArmor/Nodlink/Sysdig/model/debugfs-v1.json
# 90th
python3 main.py --d /home/hfh/A-SysArmor/Nodlink/Sysdig/model --t 51.34 --f /home/hfh/A-SysArmor/Nodlink/Sysdig/model/debugfs-v1.json
```

------------------------------------------------------------
Before that, I tried to start a docker without ```--rm```, however, I found it difficult to keep running when I ```sudo docker ps -a```, I found it couldn't be up.
```bash
sudo docker run -d \
  --name event-generator \
  --privileged \
  --pid host \
  --network host \
  -v /home/hfh/event-generator:/home/hfh/event-generator \
  ubuntu:latest \
  sleep infinity

sudo docker exec -it event-generator bash
```
