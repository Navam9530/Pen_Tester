import json
import openai, logging, requests

OPENAI_TIMEOUT_LIMIT = 35
OPENAI_TIMEOUT_RESPONSE = "We're sorry, but your request could not be completed as our language model server did not respond in time. Please try again in a few moments."
OPENAI_ERROR_RESPONSE = "We're experiencing technical difficulties connecting to our language model service. Please try again shortly. If the issue persists, contact your system administrator."
logger = logging.getLogger(__name__)

def get_llm_response(
    client: openai.AzureOpenAI,
    messages: list[dict[str, str]],
    response_format: dict | None = None,
    model: str = "gpt-4o-mini"
) -> tuple[bool, str]:

    try:
        params = {"model": model, "messages": messages, "timeout": OPENAI_TIMEOUT_LIMIT}
        if response_format:
            params["response_format"] = response_format
        response = client.chat.completions.create(**params)
        return True, response.choices[0].message.content

    except openai.APITimeoutError:
        logger.exception(OPENAI_TIMEOUT_RESPONSE)
        return False, OPENAI_TIMEOUT_RESPONSE
    except Exception:
        logger.exception(OPENAI_ERROR_RESPONSE)
        return False, OPENAI_ERROR_RESPONSE

def call_api(api_info) -> str:
    if isinstance(api_info, str):
        api_info = json.loads(api_info)
    endpoint = api_info.get("endpoint")
    method = api_info.get("method", "GET").upper()
    headers = api_info.get("headers", {})
    payload = api_info.get("payload")
    timeout = api_info.get("timeout", 10)
    
    try:
        if method == "GET":
            response = requests.get(endpoint, headers=headers, timeout=timeout)
        elif method == "POST":
            response = requests.post(endpoint, headers=headers, json=payload, timeout=timeout)
        elif method == "PUT":
            response = requests.put(endpoint, headers=headers, json=payload, timeout=timeout)
        elif method == "DELETE":
            response = requests.delete(endpoint, headers=headers, timeout=timeout)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
        
        try:
            json_response = response.json()
            full_body = json.dumps(json_response)
            return full_body if len(full_body) < 5000 else full_body[:5000] + "\n... <Response Truncated>"
        except ValueError:
            full_body = response.text
            return full_body if len(full_body) < 5000 else full_body[:5000] + "\n... <Response Truncated>"
    except Exception as e:
        logger.exception("Request Exception")
        return str(e)

def agent_1_prompt(called_apis):
    return f"""
    You are an intelligent API Caller and Security Tester. Your goal is to interact with a given 'Callable API' to understand its functionality and evaluate it for potential security weaknesses.

    You have access to 'Called APIs' (observed network traffic) which may contain valid headers, tokens, or usage patterns. Use this context to construct valid requests.

    **Your Objectives:**
    1. **Functionality Discovery**: Try to successfully call the API to understand what it does.
    2. **Security Evaluation**: Perform structured, defensive security assessments across the following categories:

       **A. Input & Data Handling Evaluations**
       - **Parameter Consistency Review**: Check how the API behaves when parameters are modified.  
         *Example:* Changing `price=10` to `price=1` should not bypass backend validation.
       - **Structured Query Handling Assessment (SQL)**: Ensure unusual characters do not cause database errors.  
         *Example:* Input should not break SQL operations.
       - **Document Database Input Validation (NoSQL)**: Validate that input is not treated as operators.  
         *Example:* Sending `"$ne": ""` should be rejected.
       - **Template Processing Evaluation (SSTI)**: Ensure template engines handle input safely.  
         *Example:* Dynamic content in emails should not be interpreted as template code.
       - **XML Data Handling Validation**: Confirm XML parsers don't fetch external resources.  
         *Example:* Uploaded XML should not reference system files.
       - **File Input Safety Check**: Validate file uploads.  
         *Example:* Prevent oversized or unsupported file types.

       **B. Access Control & Authentication Evaluations**
       - **Object-Level Access Evaluation**: Confirm a user cannot access another's resources.  
         *Example:* `/users/123` should not reveal `/users/124`.
       - **Function-Level Permission Validation**: Ensure privileged endpoints aren't accessible by normal users.  
         *Example:* `/admin/deleteUser` should remain protected.
       - **Authentication Integrity Verification**: Validate that missing or invalid credentials deny access.  
         *Example:* Removing an Authorization header should fail.
       - **Token Integrity & Validation Review (JWT)**: Ensure tokens can't be tampered with.  
         *Example:* Modifying claims should invalidate the token.
       - **Authorization Protocol Workflow Examination (OAuth)**: Validate proper OAuth flow behavior.  
         *Example:* Redirect URIs must be trusted.

       **C. Stateful & Workflow Evaluations**
       - **Business Logic Robustness Review**: Confirm workflow steps can't be bypassed.  
         *Example:* Checkout cannot finish without payment.
       - **Duplicate Request Handling Review**: Ensure repeated submissions don't cause unintended duplication.  
         *Example:* Payment should not process twice.
       - **Cross-Site Request Validation (CSRF)**: Validate that state-changing operations require proper verification.  
         *Example:* External sites should not trigger user actions.

       **D. Network, Protocol & Resource Evaluations**
       - **Internal Request Redirection Review (SSRF)**: Validate URL fetchers cannot access internal systems.  
         *Example:* Prevent calls to internal IP ranges.
       - **Usage Rate & Throttling Assessment**: Ensure rate limits are applied.  
         *Example:* Excessive login attempts should slow or block.
       - **Credential Input Load Testing**: Validate safe handling of repeated login attempts.  
         *Example:* Trigger lockouts or throttles correctly.
       - **Frontend-Backend Request Synchronization Review**: Ensure consistent request parsing across layers.  
         *Example:* Reverse proxy and backend should interpret requests identically.
       - **Response Stream Consistency Review**: Confirm that unexpected characters in headers do not affect output.  
         *Example:* Response boundaries should remain stable.
       - **Cache Behavior Reliability Review**: Verify responses aren't shared improperly.  
         *Example:* Cache should isolate per user/session.
       - **Query Depth & Complexity Evaluation (GraphQL)**: Limit excessive or deeply nested queries.  
         *Example:* High-complexity queries should be rejected.

       **E. Client-Side Interaction Evaluations**
       - **Client-Side Rendering Safety Check**: Validate that API data is safe when displayed in browsers.  
         *Example:* Profile fields should not embed dangerous markup.

       **F. Advanced Evaluation Categories**
       - **Automatic Field Binding Review (Mass Assignment)**: Confirm the API ignores unauthorized fields.  
         *Example:* Submitting `"isAdmin": true` should not elevate privileges.
       - **Instruction Interpretation Safety Review (Prompt-Driven APIs)**: Ensure APIs do not treat user content as privileged instructions.  
         *Example:* User-provided text should not alter system-level behavior.

    **Instructions:**
    - Analyze the 'Callable API' definition (which is statically extracted and might be incomplete).
    - Look at 'Called APIs' to see if there are matching hosts or authentication headers (like Authorization, X-API-Key, Cookie) you can reuse.
    - If a request fails, analyze the error and adjust your parameters.
    - Try different parameter variations, payload structures, and data formats to evaluate robustness.
    - Output ONLY the JSON object matching the `api_info` schema.

    **Context - Called APIs (Observed Traffic):**
    {called_apis}
    """

def agent_1_schema():
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "api_info",
            "schema": {
                "type": "object",
                "properties": {
                    "endpoint": {
                        "type": "string",
                        "description": "The fully qualified API URL including path and query parameters."
                    },
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                        "description": "HTTP method for the request."
                    },
                    "headers": {
                        "type": "object",
                        "description": "Optional HTTP headers.",
                        "additionalProperties": {"type": "string"}
                    },
                    "payload": {
                        "oneOf": [{"type": "object", "additionalProperties": False}, {"type": "null"}],
                        "description": "Optional JSON body for POST/PUT/PATCH requests."
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Optional timeout in seconds for the API call.",
                        "default": 10
                    }
                },
                "required": ["endpoint", "method"],
                "additionalProperties": False
            },
            "strict": False
        }
    }

def agent_2_prompt(called_apis):
    return f"""
    You are an API Security Analyst. You will be provided with the interaction history of an API and your goal is to find the attacks used and the vulnerabilities exploited from the list below:
    
    **Attacks:**
        * Broken Object-Level Authorization: Accessing or modifying another user's data by manipulating object identifiers.
        * Broken Function-Level Authorization: Calling actions or endpoints meant for higher-privileged roles (e.g., admin functions).
        * Authentication Bypass: Gaining access without valid credentials due to flawed auth logic or missing checks.
        * Parameter Tampering: Manipulating request parameters (query, body, headers) to alter business logic or gain unauthorized access.
        * SQL Injection: Injecting malicious SQL into input fields to manipulate or extract data from a relational database.
        * NoSQL Injection: Injecting crafted JSON/NoSQL payloads to alter NoSQL query behavior (e.g., MongoDB, Firebase).
        * Command Injection: Causing the server to execute unintended OS-level commands via unvalidated input.
        * Server-Side Template Injection: Injecting template expressions into systems that use server-side templates.
        * XML External Entity: Exploiting XML parsers to read server files or trigger SSRF-like internal network requests.
        * Server-Side Request Forgery: Making the API server send requests to internal or external systems.
        * Rate Limit Bypass: Sending excessive requests to brute force, scrape data, or overwhelm the API due to insufficient rate limits.
        * Brute Force / Credential Stuffing: Trying large sets of usernames/passwords to gain unauthorized access.
        * JWT Manipulation: Altering JSON Web Tokens (e.g., changing algorithm to "none", forging signatures).
        * OAuth Attacks: Exploiting redirect URIs, stealing authorization codes, or misusing PKCE flows.
        * Mass Assignment: Overriding protected fields (e.g., role, balance, permissions) via auto-bound parameters.
        * Business Logic Abuse: Exploiting logical flaws in workflows like checkout, password reset, or coupon use.
        * Cross-Site Request Forgery: Forcing authenticated users' browsers to make unwanted API requests.
        * XSS via API Responses: Injecting malicious scripts that are stored or reflected by API data consumed in the UI.
        * Request Smuggling: Exploiting discrepancies between front-end and back-end servers to bypass controls.
        * Response Smuggling: Manipulating responses to cause downstream servers or clients to misinterpret data.
        * Replay Attacks: Reusing intercepted valid requests or tokens to repeat actions illegitimately.
        * GraphQL Query Abuse / DoS: Sending extremely deep or complex GraphQL queries to exploit resource exhaustion.
        * Cache Poisoning: Manipulating API parameters to store malicious content in shared caches.
        * File Upload Attacks: Uploading harmful or oversized files (e.g., script files, zip bombs) to exploit backend processing.
        * Prompt Injection: Manipulating LLM-powered API prompts to alter behavior or bypass intended restrictions.
    
    **Vulnerabilities:**
        * Broken Object-Level Authorization: APIs expose object identifiers without proper access checks, allowing attackers to access other users' data.
        * Broken Authentication: Weak or improperly implemented authentication allowing unauthorized access.
        * Broken Function-Level Authorization: Missing permission checks for privileged operations (admin/premium functions).
        * SQL/NoSQL Injection: Unsanitized input modifies backend queries, exposing or corrupting data.
        * Server-Side Request Forgery: API allows attackers to force server requests to internal or external systems.
        * Mass Assignment: API automatically binds client-supplied fields, enabling overwriting of sensitive attributes.
        * Sensitive Data Exposure: API responses leak PII, tokens, configuration data, or system info.
        * Security Misconfiguration: Misconfigured CORS, open API docs, debug endpoints, verbose errors, weak TLS, etc.
        * Inadequate Rate Limiting: Allows brute force, credential stuffing, token guessing, or DoS at the API layer.
        * Unrestricted File Upload: Insecure file handling allowing malicious uploads, path traversal, or resource exhaustion.

    **Your Objectives:**
    1. For every attack you:
        - Mention the attack name.
        - Mention status as True if successful, False otherwise.
    2. For every vulnerability you find that exists in the api:
        - Mention the vulnerability name.
        - Mention the severity in the scale of 1 to 10.
        - Explain what was wrong with the API in 1-2 sentences.
    3. Only mention critical vulnerabilities that are in the list above.
    4. Keep the vulnerability list empty if none are found.

    **Instructions:**
    - Review the 'Message History' which contains the attempts made by the API Caller and the responses received.
    - Output ONLY the JSON object matching the `api_info` schema.
    
    **These are the APIs that were called when the page is loaded. These are for your reference:**
    {called_apis}
    """

def agent_2_schema():
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "api_info",
            "schema": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL of the API"
                    },
                    "attacks": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {"name": {"type": "string"}, "status": {"type": "boolean"}},
                            "required": ["name", "status"],
                            "additionalProperties": False
                        }
                    },
                    "vulnerabilities": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "severity": {"type": "number", "minimum": 1, "maximum": 10},
                                "description": {"type": "string"}
                            },
                            "required": ["name", "severity", "description"],
                            "additionalProperties": False
                        }
                    }
                },
                "required": ["url", "attacks", "vulnerabilities"],
                "additionalProperties": False
            },
            "strict": True
        }
    }

def agent_3_prompt():
    return """
    You are a Software Composition Analysis (SCA) Expert. Your goal is to analyze a block of code (JavaScript or HTML) for security risks and specify what vulnerabilities are present.

    **Vulnerabilities:**
        * Cross-Site Scripting (XSS): Injection of malicious scripts into the browser through unvalidated content.
        * DOM-Based XSS: Client-side JS manipulations allow script injection via DOM APIs.
        * Insecure Direct Client-Side Decisions: Critical authorization or role logic implemented in JavaScript instead of server-side.
        * Sensitive Data Exposure in JS: Hardcoded secrets, API keys, tokens, or internal URLs in the frontend.
        * Insecure CORS Configuration: Browser allowed to send requests from malicious origins due to overly permissive CORS.
        * Weak Input Sanitization: Client-side fields not sanitized, enabling injection into backend or UI transitions.
        * CSRF Through UI Integration: UI triggers sensitive actions without CSRF protections or anti-forgery tokens.
        * Race Condition Exploits: Client-side state inconsistencies enabling double submissions or repeated transactions.
        * Insecure Third-Party Libraries: Vulnerable or outdated JS dependencies enabling injection, RCE, or supply-chain attacks.
        * Clickjacking Vulnerability: UI unintentionally rendered inside attacker-controlled iframe due to missing X-Frame-Options.

    **Your Objectives:**
    1. For every vulnerability you find that exists in the code block:
        - Mention the vulnerability name.
        - Mention the severity in the scale of 1 to 10.
        - Explain what was wrong in the code block in 1-2 sentences.
    2. Only mention critical vulnerabilities that are in the list above.
    3. Keep the vulnerability list empty if none are found.

    **Instructions:**
    - Review the 'Code Block' which contains the either HTML or JavaScript code block.
    - Output ONLY the JSON object matching the `code_info` schema.
    """

def agent_3_schema():
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "code_info",
            "schema": {
                "type": "object",
                "properties": {
                    "vulnerabilities": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "severity": {"type": "number", "minimum": 1, "maximum": 10},
                                "description": {"type": "string"}
                            },
                            "required": ["name", "severity", "description"],
                            "additionalProperties": False
                        }
                    }
                },
                "required": ["vulnerabilities"],
                "additionalProperties": False
            },
            "strict": True
        }
    }

def agent_4_prompt():
    return """
    You are a Lead Zero-Day Exploit Researcher. Your role is to generate a complete, high-value security report using the following inputs:

    - **apis_called_when_loaded** → The authenticated user's actual network traffic.
    - **apis_found_in_source_code** → APIs discovered statically and dynamically tested (may include vulnerabilities + attack results).
    - **software_composition_analysis** → File-based SCA findings.

    ---

    ## Your Objectives

    ### 1. **Synthesize All Findings**
    Combine and correlate:
    - The **Software Composition Analysis** (SCA)
    - The **APIs Found in Source Code** (static/dynamic testing)
    - The **APIs Called When Loaded** (authenticated traffic)

    ### 2. **Detect Successful Exploitations**
    From `apis_found_in_source_code.attacks`:
    - Identify any attacks where `status=True` (SQLi, XSS, File Read, etc.)
    - Treat these as *confirmed exploitable vulnerabilities*.

    ### 3. **Attack Surface Mapping**
    Using all API information:
    - List all discovered endpoints.
    - Indicate which are vulnerable, partially vulnerable, or safe.
    - Identify missing authentication, sensitive operations, or unsafe HTTP methods.

    ### 4. **Critical Broken Access Control Detection**
    Perform the following logic:

    **For each API in `apis_found_in_source_code`:**
    - If it was **NOT** called in `apis_called_when_loaded`
    - AND that API was reachable/callable during testing (implied by it appearing in the source code + attacks)
    - AND the system allowed access **without authentication**

    → Then classify this as a **CRITICAL Broken Access Control Vulnerability**.

    This means:
    - The backend relies on the frontend to hide endpoints.
    - Authentication is NOT enforced server-side.
    - The endpoint is publicly exposed to attackers.

    Your job is to strongly highlight these.

    ### 5. **Structure the Final Report**
    The output must be a **fully assembled, professional security report** in a **HTML format**.

    Include the following sections:

    ---

    ## **Report Structure**

    ### **1. Critical Vulnerabilities**
    List:
    - Confirmed exploited endpoints (`status=True` attacks)
    - Broken access control (missing authentication)
    - High-severity SCA findings

    ### **2. Sensitive Data Exposure**
    Identify:
    - Credentials
    - Tokens
    - Secrets
    - PII
    - Hardcoded sensitive information from SCA & API results

    ### **3. Attack Surface Summary**
    For each discovered API:
    - Path
    - Vulnerabilities
    - Exploitation results
    - Authentication status
    - Severity analysis

    ### **4. Recommendations**
    Provide:
    - Code-level guidance
    - Access control fixes
    - Input validation/sanitization recommendations
    - Dependency upgrade requirements

    ---

    ## Additional Rules

    - Only output the final report in HTML format without backticks.
    - Base your conclusions ONLY on the provided JSON fields.
    - Do NOT assume endpoints or vulnerabilities that are not listed.
    - Be explicit, technical, and detailed.
    - Always prioritize the detection of **Broken Access Control**, as it is the most critical finding.
    """

def clean_llm_response(text: str) -> str:
    cleaned_text = text.strip()
    if cleaned_text.startswith("``` html"):
        cleaned_text = cleaned_text[8:]
    elif cleaned_text.startswith("```html"):
        cleaned_text = cleaned_text[7:]
    elif cleaned_text.startswith("```"):
        cleaned_text = cleaned_text[3:]
    if cleaned_text.endswith("```"):
        cleaned_text = cleaned_text[:-3]  
    return cleaned_text.strip()
