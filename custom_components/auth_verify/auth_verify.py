import logging
import ipaddress
from aiohttp import web
from homeassistant.components.http.view import HomeAssistantView
from homeassistant.core import HomeAssistant

# Initialize a logger for this component
_LOGGER = logging.getLogger(__name__)


class AuthVerify(HomeAssistantView):
    url = "/api/auth_verify/{module}"  # Dynamic route with a path parameter
    name = "api:auth_verify"
    requires_auth = True

    def __init__(self, hass: HomeAssistant, config: dict) -> None:
        self.hass = hass
        self.trusted_subnet = ipaddress.ip_network(config.get("trusted_subnet"))
        self.modules = config.get("modules", [])

    async def get(self, request: web.Request, module: str):
        # Validate the client IP against the trusted subnet
        peername = request.transport.get_extra_info("peername")
        if not peername:
            _LOGGER.warning("Unable to get peername for request.")
            return None  # Drop the request silently

        client_ip = ipaddress.ip_address(peername[0])
        if client_ip not in self.trusted_subnet:
            _LOGGER.warning(f"Unauthorized access attempt from IP: {client_ip}")
            return None  # Drop the request silently

        # Look up the email for the given module
        email = next((item["email"] for item in self.modules if item["module"] == module), None)
        if not email:
            return web.json_response({"error": f"module '{module}' not found"}, status=404)

        # Return the email as the response
        return web.json_response({"email": email}, status=200)
