from mcp.server.fastmcp import FastMCP
import httpx

mcp = FastMCP("weather")


@mcp.tool()
def get_forecast(city: str) -> str:
    """Return a short weather forecast for a city.

    Pass a city name such as "Berlin" or "São Paulo". For historical
    data use the `get_history` tool instead; this tool only returns the
    current forecast.
    """
    resp = httpx.get(
        "https://api.weather.example/v1/forecast",
        params={"city": city},
        timeout=10,
    )
    data = resp.json()
    return f"{city}: {data['summary']}, {data['temp_c']}C"


if __name__ == "__main__":
    mcp.run()
