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
        # Get the original client IP from the X-Forwarded-For header
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()  # First IP in the list
            _LOGGER.debug(f"HA_AUTH_VERIFY: Original client IP from X-Forwarded-For: {client_ip}")
        else:
            # Fallback to peername if X-Forwarded-For is not present
            peername = request.transport.get_extra_info("peername")
            if not peername:
                _LOGGER.warning("HA_AUTH_VERIFY: Unable to get peername for request.")
                return None  # Drop the request silently
            client_ip = peername[0]
            _LOGGER.debug(f"HA_AUTH_VERIFY: Client IP from peername: {client_ip}")

        # Check if the client IP is in the trusted subnet
        try:
            client_ip_obj = ipaddress.ip_address(client_ip)
            if client_ip_obj not in self.trusted_subnet:
                _LOGGER.warning(f"HA_AUTH_VERIFY: Unauthorized access attempt from IP: {client_ip}")
                return None  # Drop the request silently
        except ValueError as e:
            _LOGGER.error(f"HA_AUTH_VERIFY: Invalid client IP: {client_ip}, Error: {e}")
            return None  # Drop the request silently

        # Look up the email for the given module
        email = next((item["email"] for item in self.modules if item["module"] == module), None)
        if not email:
            return web.json_response({"error": f"module '{module}' not found"}, status=404)

        # Return the email as the response
        return web.json_response({"email": email}, status=200)
