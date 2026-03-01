import logging, os, json
from logging.handlers import RotatingFileHandler
from sheets import push_to_sheets
from utils import (
    download_html_js, beautify_js, extract_callable_apis_using_ast, capture_all_api_calls,
    split_js_blocks, split_html_blocks
)
from agents import (
    agent_1_schema, agent_2_schema, agent_3_schema, get_llm_response, call_api,
    agent_1_prompt, agent_2_prompt, agent_3_prompt, agent_4_prompt, clean_llm_response
)
from openai import AzureOpenAI

api_version = os.getenv("AZURE_OPENAI_API_VERSION")
azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
api_key = os.getenv("AZURE_OPENAI_API_KEY")
client = AzureOpenAI(api_version=api_version, azure_endpoint=azure_endpoint, api_key=api_key)
logger = logging.getLogger(__name__)

def setup_logging() -> None:
    file_handler = RotatingFileHandler(
        filename="logs.log",
        maxBytes=10_000_000,
        backupCount=5,
        encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s:%(lineno)d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    if root_logger.hasHandlers():
        return
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    for logger_name in ["httpcore", "openai", "httpx", "asyncio", "urllib3"]:
        logging.getLogger(logger_name).propagate = False

async def get_report(url: str):
    output = {}
    output["url"] = url

    # ============================== FLOW 1 ==============================

    # Download HTML, JS files
    success, response = download_html_js(url)
    if not success:
        return None

    # Extract called APIs
    called_apis = await capture_all_api_calls(url)
    output["apis_called_when_loaded"] = called_apis
    logger.debug(f"Called APIs:\n{called_apis}")
    logger.info(f"Found total called APIs: {len(called_apis)}")

    # Extract callable APIs
    total_callable_apis = []
    files = os.listdir(response)
    for file in files:
        logger.info(f"Processing file: {file}")
        file_path = os.path.join(response, file)
        if not file.endswith("js"):
            continue
        try:
            beautify_js(file_path)
            callable_apis = extract_callable_apis_using_ast(file_path)
        except Exception:
            logger.exception("Failed to extract API calls")
            continue
        total_callable_apis.extend(callable_apis)
    logger.debug(f"Callable APIs:\n{total_callable_apis}")
    logger.info(f"Found total callable APIs: {len(total_callable_apis)}")

    # Generate API Summaries
    api_summaries = []
    for i, callable_api in enumerate(total_callable_apis):

        # Agent-1: Call a callable API
        logger.info(f"Processing API {i+1}/{len(total_callable_apis)}")
        logger.debug(f"Callable API:\n{callable_api}")
        messages = [
            {"role": "system", "content": agent_1_prompt(called_apis)},
            {"role": "user", "content": f"Callable API:\n\n{callable_api}"}
        ]
        for j in range(10):

            # Ask LLM for API
            logger.info(f"Calling API {j+1}/10")
            success, llm_response = get_llm_response(client, messages, agent_1_schema())
            if not success or not llm_response:
                continue
            logger.debug(f"LLM Response:\n{llm_response}")
            messages.append({"role": "assistant", "content": llm_response})

            # Call the API
            api_response = call_api(llm_response)
            logger.debug(f"API Response:\n{api_response}")
            messages.append({"role": "user", "content": api_response})
        
        # Agent-2: Summarize the API
        logger.info(f"Summarizing API {i+1}/{len(total_callable_apis)}")
        messages = [
            {"role": "system", "content": agent_2_prompt(called_apis)},
            {"role": "user", "content": f"Message History:\n\n{messages}"}
        ]
        success, llm_response = get_llm_response(client, messages, agent_2_schema())
        if not success:
            continue
        if isinstance(llm_response, str):
            llm_response = json.loads(llm_response)
        api_summaries.append({
            "api_name": llm_response["url"],
            "attacks": llm_response["attacks"],
            "vulnerabilities": llm_response["vulnerabilities"]
        })
    output["apis_found_in_source_code"] = api_summaries
    logger.debug(f"API Summaries:\n{api_summaries}")

    # ============================== FLOW 2 ==============================

    # Software Composition Analysis
    file_summaries = []
    for root, _, files in os.walk(response):
        for file in files:
            logger.info(f"Processing file: {len(file_summaries) + 1}/{len(files)}")
            file_path = os.path.join(root, file)
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()
            blocks = split_html_blocks(code) if file.endswith(".html") else split_js_blocks(code)

            # Agent-3: Summarize a file (Sum of blocks)
            block_summaries = []
            for i, block in enumerate(blocks):
                logger.info(f"Summarizing block {i+1}/{len(blocks)}")
                messages = [
                    {"role": "system", "content": agent_3_prompt()},
                    {"role": "user", "content": f"Code Block:\n\n{block}"}
                ]
                success, llm_response = get_llm_response(client, messages, agent_3_schema())
                if not success:
                    continue
                if isinstance(llm_response, str):
                    llm_response = json.loads(llm_response)
                logger.debug(f"LLM Response:\n{llm_response}")
                block_summaries.extend(llm_response["vulnerabilities"])
            file_summaries.append({"file_name": file, "vulnerabilities": block_summaries})
    logger.debug(f"File Summaries:\n{file_summaries}")
    output["software_composition_analysis"] = file_summaries

    # Agent-4: Generate final report
    logger.info("Generating final report")
    messages = [
        {"role": "system", "content": agent_4_prompt()},
        {"role": "user", "content": f"Total Information:\n\n{output}"}
    ]
    _, llm_response = get_llm_response(client, messages)
    llm_response = clean_llm_response(llm_response)
    output["report"] = llm_response
    logger.debug(f"Final Report:\n{output}")

    # Push to Google Sheets
    try:
        logger.info("Pushing data to Google Sheets...")
        push_to_sheets(output, "Security Scan Results")
        logger.info("Data pushed to Google Sheets successfully")
    except Exception as e:
        logger.error(f"Failed to push to Google Sheets: {e}")

    return output
