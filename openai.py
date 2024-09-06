from langchain_google_genai import GoogleGenerativeAI
from typing import List
from langchain.output_parsers import PydanticOutputParser
from langchain.prompts import PromptTemplate
from langchain_core.pydantic_v1 import BaseModel, Field, validator


class llmoutput(BaseModel):

    boolean: bool = Field(description = "True for Potential Sensitive Data Movement and False for secure data movements")
    description: str = Field(description="Explain in detail how the network traffic is secure or have Sensitive Data Movement")


def prompt(url, Request, body):
    
    google_api_key = "your api key"
    # llm = GooglePalm(google_api_key=google_api_key)
    llm = GoogleGenerativeAI(model="models/text-bison-001", google_api_key=google_api_key)

    

    llm.temperature = 0.1

    prompt_ = """
    You are a cyber security expert and your task is to analyse traffic for potential threats, observe url and request body carefully.
    Task: Analyze the provided HTTPS request and response data captured using BurpSuite for potential vulnerabilities across the following categories:

    Examples:
    Malicious requests may include attempts to exploit known vulnerabilities, such as SQL injection or XSS attacks.
    Benign requests may include legitimate user interactions with the website, such as accessing resources or submitting form data.

    Feedback and Iteration:
    Review classification results and provide feedback to refine the model's understanding of malicious and benign requests.
    Adjust the prompt and classification criteria based on the performance of the model and real-world feedback.

    Validation:
    Validate classification results against ground truth labels or expert analysis to ensure accuracy and reliability

    OWASP Compliance: Targets at least 5-6 different vulnerabilities listed in the OWASP Top 10, including misconfiguration, cross-site scripting (XSS), SQL injection, and sensitive data movement.
    Misconfiguration: Identify indicators of improper server configuration, outdated software versions, unnecessary headers, debug modes, or other insecure settings.
    Cross-Site Scripting (XSS): Detect suspicious patterns, encoding issues, and injection points that could enable unauthorized script execution in a user's browser.
    SQL Injection: Look for unfiltered queries, data manipulation attempts, and other indicators that might allow attackers to access or manipulate database information.
    Sensitive Data Movement: Flag the transmission of sensitive information (e.g., credit card numbers, passwords) in plain text, insecure channels, or unauthorized downloads.

        Context:

    Target Website: {url}
    request: {Request}
    Request/Response Body: {body}
    
    Return True if Malicious activity present else return False if everything is safe.
    """

    parser = PydanticOutputParser(pydantic_object=llmoutput)

    prompt = PromptTemplate(
        template="Answer the user query.\n{format_instructions}\n{query}\n",
        input_variables=["query"],
        partial_variables={"format_instructions": parser.get_format_instructions()},
    )

    chain = prompt | llm | parser


    l =chain.invoke({"query": prompt_})
    type(l)
    print(l.boolean)
    return(l.boolean)