# ssh-keyonly

Connect to a remote SSH server and ensures that password-based authentication
is disabled.

```
ssh-keyonly '[2001:db8::1]:22'
```

It uses [`russh`](https://github.com/Eugeny/russh) as a memory-safe SSH
implementation and does not read any files that could interfere with
the audit, like `~/.ssh/id_ed25519`.

## How to do this with OpenSSH

Using this command may or may not work for you:

```sh
ssh -v -o IdentityAgent=none -i /dev/null 'root@2001:db8::1'
```

## License

`GPL-3.0-or-later`
