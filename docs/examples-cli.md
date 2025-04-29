# CLI Examples

## Embedding the `plauth` Command in Another `click` Program
It is possible to embed the [`plauth`](/cli-plauth) command into other programs to
present a unified experience that leverages the [planet_auth](/api)
package for client authentication plumbing.  This is done by using
a special version of the command that is configured for embedding.

When using the embedded version of the command, the outer application
must take on the responsibility of instantiating the auth context and
handling command line options so that this context may be available
to click commands that are outside the `plauth` root command.

```python linenums="1"
{% include 'cli/embed-plauth-click.py' %}
```
