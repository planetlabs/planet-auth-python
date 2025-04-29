# CLI Examples

## Embedding the `plauth` Command in Another `click` Program
It is possible to embed the [`plauth`](./cli-plauth.md) command into other programs to
present a unified experience that leverages the _Planet Auth Library_
package for client authentication plumbing.  This is done by using
a special version of the command that is configured for embedding.

When using the embedded version of the command, the outer application
must take on the responsibility of instantiating the auth context and
handling command line options so that this context may be available
to click commands that are outside the `plauth` root command.

```python linenums="1"
{% include 'cli/embed-plauth-click.py' %}
```

## Advanced Embedding
Beyond simple embedding, it is possible for an application to customize some
the appearance and behavior of the command.

For example, an application may rename commands or hide options and sub-commands
it does not wish to expose to the user.  For an extensive example of this in a
downstream application, you can look at the
[Planet SDK](https://github.com/planetlabs/planet-client-python)'s
CLI program, which both embeds the whole `plauth` command as a hidden
root level sub-command [`planet plauth`](https://github.com/planetlabs/planet-client-python/blob/main/planet/cli/cli.py),
and cherry-picks specific sub-commands to power its own
[`auth`](https://github.com/planetlabs/planet-client-python/blob/main/planet/cli/auth.py)
sub-command.  This allows the downstream application to leverage the _Planet Auth Library_,
while also using [configuration injection](./built-ins.md) to provide a smoother end-user experience
