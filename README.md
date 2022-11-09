# trivyal_pursuit
If you enjoy chasing down probably-unexploitable-but-you-can-never-be-sure vulnerabilities in Kubernetes, then you've found... something.

## Install
`git clone git@github.com:alex-hamlin/trivyal_pursuit.git`

`cd trivyal_pursuit`

`gem install bundler`

`bundle install`

## Authentication
If you can authenticate with `kubectl`, you're all set.

## Run
For a list of full commands, try:

`ruby trivyal_pursuit.rb -h`

To run in standard, find-the-bad-things mode:

`ruby trivyal_pursuit.rb --severity CRITICAL --patch_available --network_exploitable`

This will explore the cluster you're authenticated to, and highlight every image that is vulnerable to:

* a critical-severity vulnerability
* which is exploitable over the network
* and has a patch available

... and will ignore everything else.

Alternatively, if you're wondering "what do I have in my cluster vulnerable to X, specifically?"

`ruby trivyal_pursuit.rb --cve CVE-2021-31337`

This will only zoom in on that bad thing in particular, and let you know where it exists in your cluster.
