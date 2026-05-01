"""Quick API connection test."""
import asyncio, os
from dotenv import load_dotenv
from openai import AsyncOpenAI

load_dotenv()

async def test():
    client = AsyncOpenAI(
        api_key=os.getenv("OPENROUTER_API_KEY"),
        base_url="https://openrouter.ai/api/v1",
    )
    model = os.getenv("CLAUDE_MODEL", "anthropic/claude-3-haiku")
    print(f"Testing model: {model}")
    try:
        r = await client.chat.completions.create(
            model=model,
            max_tokens=50,
            timeout=30.0,
            messages=[{"role": "user", "content": "Say OK"}],
        )
        print("SUCCESS:", r.choices[0].message.content)
    except Exception as e:
        print("ERROR:", e)

    # Test with tool use
    print("\nTesting tool use...")
    try:
        r = await client.chat.completions.create(
            model=model,
            max_tokens=100,
            timeout=30.0,
            messages=[{"role": "user", "content": "Call the test_tool with name='hello'"}],
            tools=[{
                "type": "function",
                "function": {
                    "name": "test_tool",
                    "description": "A test tool",
                    "parameters": {
                        "type": "object",
                        "properties": {"name": {"type": "string"}},
                        "required": ["name"],
                    },
                }
            }],
            tool_choice={"type": "function", "function": {"name": "test_tool"}},
        )
        msg = r.choices[0].message
        if msg.tool_calls:
            print("TOOL USE SUCCESS:", msg.tool_calls[0].function.arguments)
        else:
            print("No tool call returned. Content:", msg.content)
    except Exception as e:
        print("TOOL USE ERROR:", e)

asyncio.run(test())
