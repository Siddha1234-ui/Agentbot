import os
import hashlib
import hmac
import time
from flask import Flask, request, jsonify, abort
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from openai import OpenAI

# --------------------
# Load ENV variables
# --------------------
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")   # xoxb-***
SLACK_SIGNING_SECRET = os.environ.get("SLACK_SIGNING_SECRET")  # from Slack App
SLACK_CHANNEL = os.environ.get("SLACK_CHANNEL")       # channel ID (optional)
BOT_USER_ID = os.environ.get("BOT_USER_ID")           # your bot's user id
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")

# Initialize clients
slack_client = WebClient(token=SLACK_BOT_TOKEN)
openai_client = OpenAI(api_key=OPENAI_API_KEY)

# Flask app
app = Flask(__name__)

# --------------------
# Verify Slack requests
# --------------------
def verify_slack_request(req):
    timestamp = req.headers.get("X-Slack-Request-Timestamp")
    signature = req.headers.get("X-Slack-Signature")

    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False  # request too old

    sig_basestring = f"v0:{timestamp}:{req.get_data(as_text=True)}"
    my_signature = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(),
        sig_basestring.encode(),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(my_signature, signature)


# --------------------
# Routes
# --------------------
@app.route("/", methods=["GET"])
def home():
    return "🤖 AgentBot is live on Vercel!", 200


@app.route("/slack/events", methods=["POST"])
def slack_events():
    if not verify_slack_request(request):
        abort(400, "Invalid request signature")

    data = request.get_json()

    # 1. Slack verification challenge
    if "challenge" in data:
        return jsonify({"challenge": data["challenge"]})

    # 2. Handle events
    if "event" in data:
        event = data["event"]

        # Ignore bot's own messages
        if event.get("user") == BOT_USER_ID:
            return "OK", 200

        # Reply to user messages
        if event.get("type") == "message" and "subtype" not in event:
            user = event.get("user")
            text = event.get("text")
            channel = event.get("channel")

            # Get AI reply from GPT
            try:
                completion = openai_client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are AgentBot, a helpful and friendly assistant."},
                        {"role": "user", "content": text}
                    ]
                )
                reply_text = completion.choices[0].message["content"]
            except Exception as e:
                reply_text = f"⚠️ OpenAI Error: {str(e)}"

            # Send reply back
            try:
                slack_client.chat_postMessage(channel=channel, text=reply_text)
            except SlackApiError as e:
                print(f"Slack API Error: {e.response['error']}")

    return "OK", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)