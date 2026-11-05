"""Runs INSIDE the sandbox Home Assistant container (copied there by the HA tester).

For every given domain: resolve the integration (core or custom), install its requirements (through the
sandbox egress proxy - PyPI / HA wheels only), import the component and, if it has one, its config flow.
This proves that integrations which are disabled in the sandbox (because they would talk to real devices)
would at least load with the new version. Prints one JSON object.

Usage: python3 ha_integration_check.py /config domain1 domain2 ...
"""

import asyncio
import json
import sys
import traceback


async def main(config_dir, domains):
    from homeassistant import loader, requirements
    from homeassistant.core import HomeAssistant

    try:
        hass = HomeAssistant(config_dir)
    except TypeError:  # very old signature
        hass = HomeAssistant()
        hass.config.config_dir = config_dir
    if hasattr(loader, "async_setup"):
        loader.async_setup(hass)
    results = {}
    for d in domains:
        try:
            integ = await asyncio.wait_for(requirements.async_get_integration_with_requirements(hass, d), 600)
            if hasattr(integ, "async_get_component"):
                await integ.async_get_component()
            else:
                integ.get_component()
            if getattr(integ, "config_flow", False):
                if hasattr(integ, "async_get_platform"):
                    await integ.async_get_platform("config_flow")
                else:
                    integ.get_platform("config_flow")
            results[d] = {"ok": True, "version": str(getattr(integ, "version", "") or ""),
                          "custom": not getattr(integ, "is_built_in", True)}
        except Exception as e:  # noqa: BLE001 - every failure is a result
            tb = traceback.format_exception_only(type(e), e)[-1].strip()
            results[d] = {"ok": False, "error": tb[:300]}
    print(json.dumps({"results": results}))
    try:
        await hass.async_stop(force=True)
    except Exception:  # noqa: BLE001
        pass


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], sys.argv[2:]))
