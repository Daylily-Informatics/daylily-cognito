from cli_core_yo.spec import CliSpec, ConfigSpec, PluginSpec, XdgSpec

spec = CliSpec(
    prog_name="daycog",
    app_display_name="Daycog CLI",
    dist_name="daylily-cognito",
    root_help="Cognito authentication management commands",
    xdg=XdgSpec(app_dir_name="daycog"),
    config=ConfigSpec(
        primary_filename="config.yaml",
        template_bytes=b"contexts: {}\nactive_context: \"\"\n",
    ),
    plugins=PluginSpec(
        explicit=[
            "daylily_cognito.plugins.core",
        ]
    )
)
