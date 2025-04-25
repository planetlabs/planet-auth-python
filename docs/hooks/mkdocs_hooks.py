import importlib.metadata


def on_config(config):
    """
    This is for injecting the package version into mkdocs
    config so it can be used in templates.
    """
    config["extra"]["site_version"] = importlib.metadata.version("planet-auth")
    return config
