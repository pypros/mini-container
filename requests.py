import shutil
import http.client
import urllib.parse
import ssl
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

def request(host, url, method="GET", headers={}, save_path=None):
    """
    General function for performing HTTP/HTTPS requests with manual redirect handling (3xx).
    Logic copied from DockerPuller._make_request.
    """
    MAX_REDIRECTS = 5
    redirect_count = 0
    current_host = host
    current_url = url

    while redirect_count < MAX_REDIRECTS:
        conn = None
        try:
            parsed_url = urllib.parse.urlparse(f"https://{current_host}{current_url}")
            current_host = parsed_url.netloc
            current_path = parsed_url.path + (
                "?" + parsed_url.query if parsed_url.query else ""
            )

            context = ssl.create_default_context()
            conn = http.client.HTTPSConnection(current_host, context=context)

            # KEY LOGIC FROM YOUR CLASS: Removing the Authorization header after the first redirect
            req_headers = headers.copy()
            if redirect_count > 0 and "Authorization" in req_headers:
                # After redirecting to the storage server (blobs), authorization is often built into the link
                del req_headers["Authorization"]

            conn.request(method, current_path, headers=req_headers)
            response = conn.getresponse()

            # Handling redirects (Status 3xx)
            if response.status in (301, 302, 307, 308):
                new_location = response.getheader("Location")
                if not new_location:
                    raise Exception("Redirect without Location header.")

                new_parsed_url = urllib.parse.urlparse(new_location)
                current_host = new_parsed_url.netloc
                current_url = new_parsed_url.path + (
                    "?" + new_parsed_url.query if new_parsed_url.query else ""
                )

                redirect_count += 1
                conn.close()
                continue

            if response.status == 200:
                if save_path:
                    with open(save_path, "wb") as f:
                        shutil.copyfileobj(response, f)
                    return "File saved", 200
                else:
                    data = response.read().decode("utf-8")
                    return data, 200
            else:
                error_data = response.read().decode("utf-8", errors="ignore")
                logger.error(
                    f"HTTP Status {response.status} for {current_host}{current_path}"
                )
                return error_data, response.status

        except Exception as e:
            logger.error(f"Error during request to {current_host}{current_path}: {e}")
            return None, None
        finally:
            if conn:
                conn.close()

    if redirect_count == MAX_REDIRECTS:
        logger.error("Maximum redirect limit reached.")
        return None, None

    return None, None

