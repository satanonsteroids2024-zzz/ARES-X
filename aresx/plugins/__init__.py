"""aresx.plugins — Phase 8: Plugin Architecture"""
from aresx.plugins.plugin_system import (
    BasePlugin, PluginManifest, PluginManager, plugin_manager,
)
PHASE_STATUS = "implemented"
__all__ = ["BasePlugin","PluginManifest","PluginManager","plugin_manager","PHASE_STATUS"]
