import os, uuid, logging, requests, jsbeautifier, re
from typing import Any
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from tree_sitter import Language, Parser, Node
import tree_sitter_javascript
from playwright.async_api import async_playwright

logger = logging.getLogger(__name__)

def download_html_js(url: str) -> tuple[bool, str]:
    output_folder = os.path.join("websites", str(uuid.uuid4()))
    os.makedirs(output_folder, exist_ok=True)

    # Send a GET request to the URL
    logger.info(f"-> Requesting initial URL: {url}")
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.Timeout:
        msg = "Request timed out"
        logger.exception(msg)
        return False, msg
    except requests.exceptions.SSLError:
        msg = "SSL certificate error"
        logger.exception(msg)
        return False, msg
    except requests.exceptions.ConnectionError:
        msg = "Network problem (DNS failure, refused connection, etc.)"
        logger.exception(msg)
        return False, msg
    except requests.exceptions.HTTPError as e:
        msg = f"HTTP error occurred: {e.response.status_code}"
        logger.exception(msg)
        return False, msg
    except requests.exceptions.URLRequired:
        msg = "A valid URL is required"
        logger.exception(msg)
        return False, msg
    except requests.exceptions.TooManyRedirects:
        msg = "Too many redirects — check the URL"
        logger.exception(msg)
        return False, msg
    except requests.exceptions.RequestException:
        msg = "General error fetching URL"
        logger.exception(msg)
        return False, msg
    final_url = response.url
    logger.info(f"-> Final destination URL used for resolving assets: {final_url}")

    # Save the main HTML file
    html_filename = os.path.join(output_folder, "index.html")
    with open(html_filename, 'w', encoding='utf-8') as f:
        f.write(response.text)
    logger.info(f"Saved main HTML to: {html_filename}")

    # Parse HTML and find relevant assets (JavaScript)
    asset_urls = set()
    soup = BeautifulSoup(response.text, 'html.parser')
    for script in soup.find_all('script', src=True):
        asset_urls.add(script['src'])
    logger.info(f"-> Found {len(asset_urls)} unique JavaScript files. Starting download...")
    
    # Download each unique asset
    for asset_path in asset_urls:
        full_asset_url = urljoin(final_url, asset_path)
        parsed_asset = urlparse(full_asset_url)
        asset_filename = os.path.basename(parsed_asset.path)
        
        # Skip non-JS files
        if not asset_filename or not asset_filename.endswith(('.js', '.mjs', '.cjs')):
            continue

        # Download the asset
        local_filepath = os.path.join(output_folder, asset_filename)
        try:
            asset_response = requests.get(full_asset_url, timeout=10)
            asset_response.raise_for_status()
            with open(local_filepath, 'wb') as f:
                f.write(asset_response.content)
            logger.info(f"Downloaded: {asset_filename}")
        except requests.exceptions.RequestException:
            logger.exception(f"Failed to download {full_asset_url}")
    logger.info("Download process complete")
    return True, output_folder

def beautify_js(file_path: str) -> bool:

    # Read
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            js_code = f.read()
    except Exception:
        logger.exception("Failed to read file")
        return False

    # Format
    results = jsbeautifier.beautify(js_code)

    # Write
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(results)
    except Exception:
        logger.exception("Failed to write to file")
        return False
    return True

def extract_callable_apis_using_regex(file_path: str) -> list[str]:
    patterns = [
        r'fetch\s*\(\s*[\'"]([^\'"]+)[\'"]',                       # fetch("...")
        r'fetch\s*\(\s*`([^`]+)`',                                 # fetch(`...`)
        r'axios\.\w+\s*\(\s*[\'"]([^\'"]+)[\'"]',                  # axios.get("...")
        r'axios\.\w+\s*\(\s*`([^`]+)`',                            # axios.get(`...`)
        r'\$\.ajax\s*\(\s*\{\s*url\s*:\s*[\'"]([^\'"]+)[\'"]',     # $.ajax url
        r'[\'"](https?://[^\'"]+)[\'"]',                           # absolute URLs
        r'`(https?://[^`]+)`',                                     # absolute URLs in template literal
        r'[\'"](/[^\'"]+)[\'"]',                                   # "/something"
        r'`(/[^`]+)`',                                             # template literal "/something"
        r'(?:baseUrl|baseURL)\s*\+\s*[\'"]([^\'"]+)[\'"]',         # baseUrl + "/path"
        r'[\'"]([^\'"]+)\s*\+\s*(?:baseUrl|baseURL)[\'"]',         # "/path" + baseUrl
    ]

    # Read
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        logger.exception("Error reading file")
        return []

    # Search
    endpoints = set()
    for pattern in patterns:
        try:
            matches = re.findall(pattern, content)
            for m in matches:
                endpoints.add(m.strip())
        except Exception:
            continue
    return sorted(endpoints)

def get_node_text(source: bytes, node):
    return source[node.start_byte:node.end_byte].decode("utf8")

def extract_object_literal(source: bytes, node: Node):
    result = {}
    if node.type != "object":
        return result
    for prop in node.named_children:
        if prop.type == "pair":
            key_node = prop.child_by_field_name("key")
            value_node = prop.child_by_field_name("value")
            # Handle keys that might be identifiers or strings
            key = get_node_text(source, key_node)
            # Remove quotes if key is a string literal
            if key.startswith(("'", '"')) and key.endswith(("'", '"')):
                key = key[1:-1]
            # Simple value extraction (can be improved for nested objects)
            value_text = get_node_text(source, value_node)
            # Remove quotes for string values
            if value_text.startswith(("'", '"')) and value_text.endswith(("'", '"')):
                value_text = value_text[1:-1]
            result[key] = value_text
    return result

def traverse(node: Node, source_bytes: bytes, api_calls: list[dict[str, Any]]):

    # Case 1: fetch(url, options)
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func and func.type == "identifier" and get_node_text(source_bytes, func) == "fetch":
            if args and args.named_child_count > 0:
                url_node = args.named_children[0]
                url = get_node_text(source_bytes, url_node)
                if url.startswith(("'", '"')) and url.endswith(("'", '"')): # Clean up quotes
                    url = url[1:-1]
                api = {"url": url, "method": "GET"} # Default to GET
                options = args.named_children[1] if args.named_child_count > 1 else None
                if options and options.type == "object":
                    opts = extract_object_literal(source_bytes, options)
                    if "method" in opts:
                        api["method"] = opts["method"].upper()
                    if "headers" in opts:
                        api["headers"] = opts["headers"]
                    if "body" in opts:
                        api["payload"] = opts["body"]
                api_calls.append(api)

    # Case 2: axios.get(url, data), axios.post(url, data), axios({...})
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        
        # axios.get / axios.post style
        if func and func.type == "member_expression":
            obj = func.child_by_field_name("object")
            prop = func.child_by_field_name("property")
            if obj and get_node_text(source_bytes, obj) == "axios":
                method = get_node_text(source_bytes, prop).upper()
                args = node.child_by_field_name("arguments")
                if args and args.named_child_count > 0:
                    url_node = args.named_children[0]
                    url = get_node_text(source_bytes, url_node)
                    if url.startswith(("'", '"')) and url.endswith(("'", '"')): url = url[1:-1]
                    payload = None
                    headers = None
                    
                    # axios.post(url, data, config)
                    if method in ["POST", "PUT", "PATCH"] and args.named_child_count > 1:
                        payload = get_node_text(source_bytes, args.named_children[1])
                        if args.named_child_count > 2:
                            config_node = args.named_children[2]
                            if config_node.type == "object":
                                config = extract_object_literal(source_bytes, config_node)
                                headers = config.get("headers")

                    # axios.get(url, config)
                    elif method in ["GET", "DELETE"] and args.named_child_count > 1:
                        config_node = args.named_children[1]
                        if config_node.type == "object":
                            config = extract_object_literal(source_bytes, config_node)
                            headers = config.get("headers")
                            # params could be here too

                    api_call = {"method": method, "url": url}
                    if payload:
                        api_call["payload"] = payload
                    if headers:
                        api_call["headers"] = headers
                    api_calls.append(api_call)

        # axios({ method, url, ... })
        if func and func.type == "identifier" and get_node_text(source_bytes, func) == "axios":
            args = node.child_by_field_name("arguments")
            if args and args.named_child_count > 0 and args.named_children[0].type == "object":
                opts = extract_object_literal(source_bytes, args.named_children[0])
                api_call = {"method": opts.get("method", "GET").upper(), "url": opts.get("url")}
                if opts.get("headers"):
                    api_call["headers"] = opts.get("headers")
                payload = opts.get("data") or opts.get("body")
                if payload:
                    api_call["payload"] = payload
                api_calls.append(api_call)

    # Case 3: Generic Heuristic (obj.get('/api/...'), obj.post(...))
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        if func and func.type == "member_expression":
            prop = func.child_by_field_name("property")
            method_name = get_node_text(source_bytes, prop)
            if method_name in ["get", "post", "put", "delete", "patch", "fetch"]:
                args = node.child_by_field_name("arguments")
                if args and args.named_child_count > 0:
                    first_arg = args.named_children[0]
                    arg_text = get_node_text(source_bytes, first_arg)
                    url = None
                    path_params = []

                    # Check if first argument is a string literal
                    if first_arg.type == "string":
                        if arg_text.startswith(("'", '"')) and arg_text.endswith(("'", '"')):
                            url = arg_text[1:-1]
                    
                    # Check if first argument is a template string (path params)
                    elif first_arg.type == "template_string":
                        url = arg_text # Keep the full template string as URL representation
                        # Extract substitutions as path params
                        for child in first_arg.children:
                            if child.type in ["substitution", "template_substitution"]:
                                path_params.append(get_node_text(source_bytes, child))

                    if url:
                        # Heuristic: must start with / or http or be a known API path pattern or contain substitutions
                        if url.startswith(("/", "http", "https")) or "/api/" in url or len(path_params) > 0:
                            method_upper = method_name.upper()
                            payload = None
                            headers = None
                            query_params = None

                            # Extract Payload and Config based on method
                            config_node = None
                            if method_upper in ["POST", "PUT", "PATCH"]:
                                if args.named_child_count > 1:
                                    payload = get_node_text(source_bytes, args.named_children[1])
                                if args.named_child_count > 2:
                                    config_node = args.named_children[2]
                            elif method_upper in ["GET", "DELETE"]:
                                if args.named_child_count > 1:
                                    config_node = args.named_children[1]

                            # Extract details from config object
                            if config_node and config_node.type == "object":
                                config = extract_object_literal(source_bytes, config_node)
                                headers = config.get("headers")
                                query_params = config.get("params") # Common in axios

                            # Avoid duplicates
                            is_duplicate = False
                            for existing in api_calls:
                                if existing.get("url") == url and existing.get("method") == method_upper:
                                    is_duplicate = True
                                    break
                            if not is_duplicate:
                                api_call: dict[str, Any] = {"method": method_upper, "url": url}
                                if payload: api_call["payload"] = payload
                                if headers: api_call["headers"] = headers
                                if query_params: api_call["queryParams"] = query_params
                                if path_params: api_call["pathParams"] = path_params
                                api_calls.append(api_call)
    # Continue traversal
    for child in node.children:
        traverse(child, source_bytes, api_calls)

def extract_callable_apis_using_ast(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        source_code = f.read()
    source_bytes = source_code.encode('utf8')
    parser = Parser(Language(tree_sitter_javascript.language()))
    tree = parser.parse(source_bytes)
    root = tree.root_node
    api_calls = []
    traverse(root, source_bytes, api_calls)
    return api_calls

async def capture_all_api_calls(url: str) -> list[dict]:
    api_calls = []

    # Run Chromium headlessly
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        request_map = {}

        # Event to capture XHR/fetch requests
        async def handle_request(request):
            if request.resource_type in ["xhr", "fetch"]:
                parsed = urlparse(request.url)
                request_data = {
                    "method": request.method,
                    "url": request.url,
                    "path": parsed.path,
                    "query_params": parse_qs(parsed.query),
                    "headers": request.headers,
                    "payload": request.post_data or None,
                    "response_status": None,
                    "response_headers": None,
                    "response_body": None,
                }
                request_map[request] = request_data
                api_calls.append(request_data)

        # Event to capture responses
        async def handle_response(response):
            request = response.request
            if request in request_map:
                try:
                    full_body = await response.text()
                    body = full_body if len(full_body) < 5000 else full_body[:5000] + "\n... <Response Truncated>"
                except Exception:
                    body = None
                request_map[request].update({
                    "response_status": response.status,
                    "response_headers": response.headers,
                    "response_body": body
                })

        # Add event listeners
        page.on("request", handle_request)
        page.on("response", handle_response)
        await page.goto(url, wait_until="networkidle")

        # Interact with clickable elements
        elements = await page.query_selector_all("*")
        for el in elements:
            try:
                if not await el.is_visible():
                    continue
                if await el.bounding_box() is None:
                    continue
                await el.scroll_into_view_if_needed()
                await el.click(timeout=500)
                await page.wait_for_timeout(700)
            except Exception:
                continue
        await browser.close()
    return api_calls

def split_js_blocks(code, max_tokens=5000):
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
    except ImportError:
        enc = None

    # Regex for functions, classes, arrow functions
    pattern = r'(?:function\s+\w+\s*\([^)]*\)\s*\{)|(?:class\s+\w+\s*\{)|(?:\w+\s*=\s*\([^)]*\)\s*=>\s*\{)'
    matches = list(re.finditer(pattern, code, re.MULTILINE))

    blocks = []
    last_idx = 0
    for m in matches:
        start = m.start()
        if start > last_idx:
            blocks.append(code[last_idx:start].strip())
        last_idx = start
    blocks.append(code[last_idx:].strip())
    blocks = [b for b in blocks if b]

    # Further split large blocks by tiktoken
    if enc:
        final_blocks = []
        for block in blocks:
            tokens = enc.encode(block)
            if len(tokens) <= max_tokens:
                final_blocks.append(block)
            else:
                # Split into chunks
                start = 0
                while start < len(tokens):
                    end = min(start + max_tokens, len(tokens))
                    chunk = enc.decode(tokens[start:end])
                    final_blocks.append(chunk)
                    start += max_tokens  # no overlap
        return final_blocks
    
    # Fallback: character-based split (~4 chars per token)
    else:
        final_blocks = []
        for block in blocks:
            if len(block) <= max_tokens * 4:
                final_blocks.append(block)
            else:
                start = 0
                chunk_size = max_tokens * 4
                while start < len(block):
                    end = min(start + chunk_size, len(block))
                    final_blocks.append(block[start:end])
                    start += chunk_size
        return final_blocks

def split_html_blocks(code, max_tokens=5000):
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
        tokens = enc.encode(code)
        if len(tokens) <= max_tokens:
            return [code]
        blocks = []
        start = 0
        while start < len(tokens):
            end = min(start + max_tokens, len(tokens))
            blocks.append(enc.decode(tokens[start:end]))
            start += max_tokens
        return blocks

    except ImportError:
        # Character-based fallback
        if len(code) <= max_tokens * 4:
            return [code]
        blocks = []
        start = 0
        chunk_size = max_tokens * 4
        while start < len(code):
            end = min(start + chunk_size, len(code))
            blocks.append(code[start:end])
            start += chunk_size
        return blocks
