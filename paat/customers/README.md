# customers/

Empty on purpose. A fresh PAAT install has **no customers, devices or users**; you add your own.

* Server install: customer profiles live in `/etc/paat/customers/<name>/profile.yaml`.
* Container: mount a folder at `/etc/paat/customers`.
* Start from `profile.example.yaml` in this folder: copy it, rename it, edit it.

Profiles hold only *names of environment variables* for hosts and API keys, never the values.
