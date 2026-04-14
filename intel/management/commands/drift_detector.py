import requests

'''
This is a simple script to check the routes in readme still exist and generate a cli report of any that don't. This is to help detect drift between the readme and the actual codebase.


the routes are below:

- `/auth/login/`: login page
- `/auth/register/`: self-service local registration page, defaults new users to `viewer`
- `/auth/logout/`: logout endpoint
- `/` and `/dashboard/`: dashboard, requires `viewer` or higher
- `/assistant/`: analyst assistant page, requires `analyst` or higher
- `/api/assistant/chat/`: assistant API endpoint (POST), requires authenticated `analyst` or higher
- `/api/assistant/context/`: assistant context API endpoint (POST), requires analyst auth or a valid `X-ThreatFoundry-Service-Token`
- `/docs/`: in-app docs browser, requires `viewer` or higher
- `/docs/<doc_name>/`: specific doc page, requires `viewer` or higher
- `/malware/`: malware directory and family view, requires `viewer` or higher
- `/ioc-blade/`: aggregated IOC blade detail, requires `viewer` or higher
- `/ioc/<pk>/`: IOC detail, requires `viewer` or higher
- `/admin/`: Django admin


'''

route = [
    "/auth/login/",
    "/auth/register/",
    "/auth/logout/",
    "/",
    "/dashboard/",
    "/assistant/",
    "/api/assistant/chat/",
    "/api/assistant/context/",
    "/docs/",
    "/docs/some-doc/",
    "/malware/",
    "/ioc-blade/",
    "/ioc/1/",  # Example IOC detail route
    "/admin/"
]


def check_route(route):
    url = f"http://localhost:8080{route}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"✅ {route} exists")
        # some routes need a post so we can check for 405 method not allowed as an indicator the route exists but doesn't support GET
        elif response.status_code == 405:
            print(f"✅ {route} exists (POST only)")
        else:
            print(f"❌ {route} returned status code {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"❌ {route} check failed with error: {e}")
        

def route_report():
    print("Route Drift Detection Report")
    print("============================")
    for r in route:
        check_route(r)


if __name__ == "__main__":
    route_report()


