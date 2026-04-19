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
