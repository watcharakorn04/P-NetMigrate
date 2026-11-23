"""Per-vendor renderers (IR -> target text). Renderers never read source text."""

from app.core.ir import DeviceConfigIR, RenderedLine, Vendor
from app.core.renderers import cisco_iosxe, huawei_vrp

_RENDERERS = {Vendor.CISCO_IOS_XE: cisco_iosxe.render, Vendor.HUAWEI_VRP: huawei_vrp.render}


def render_config(ir: DeviceConfigIR, target: Vendor) -> list[RenderedLine]:
    return _RENDERERS[target](ir)


__all__ = ["render_config"]
