"""
Streamlit Test Harness – Agentic Honey-Pot System

This UI allows manual testing of the Honey-Pot system via its public API.
It strictly adheres to the 'api_contract.md' and does not bypass the backend logic.

KEY FEATURES:
- Simulates Scammer behavior (sending messages)
- Displays Agent responses and state transitions
- Visualizes extracted intelligence and session lifecycle flags
- Persists session ID to support multi-turn conversations
"""

import streamlit as st
import requests
import uuid
import json
import os

# --- Configuration ---
API_URL = "http://localhost:8000/honeypot/message"
API_KEY = "YOUR_SECRET_API_KEY"  # Matches backend default

# --- Session State Initialization ---
if "session_id" not in st.session_state:
    st.session_state.session_id = f"manual-test-{uuid.uuid4().hex[:8]}"

if "conversation_history" not in st.session_state:
    st.session_state.conversation_history = []

if "last_response_data" not in st.session_state:
    st.session_state.last_response_data = None

# --- UI Layout ---
st.set_page_config(page_title="HoneyPot Tester", layout="wide")
st.title("🍯 Agentic Honey-Pot Test Interface")

# --- Sidebar: Configuration & Debug ---
with st.sidebar:
    st.header("Configuration")
    
    # Environment Controls (Note: In a real deployment, these would need to set env vars on the server)
    # Since we can't change server env vars from here easily, we act as a client.
    # Ideally, we'd restart the server with these flags, but for now we just display them.
    st.info("Ensure Backend is running with correct Env Vars if you want to switch LLM modes.")
    
    st.header("Session Debug Info")
    st.text(f"Session ID: {st.session_state.session_id}")
    
    if st.button("New Session"):
        st.session_state.session_id = f"manual-test-{uuid.uuid4().hex[:8]}"
        st.session_state.conversation_history = []
        st.session_state.last_response_data = None
        st.rerun()

    # Display Debug Data from Last Response
    if st.session_state.last_response_data:
        data = st.session_state.last_response_data
        
        st.subheader("State")
        # Note: We can infer state from the previous turn or logs, but the API 
        # contract doesn't return 'agentState' explicitly in the root (it returns extractedIntelligence etc).
        # Wait, let's check api_contract.md.
        # It returns 'agentReply' and 'extractedIntelligence'. 
        # To know 'agentState', we might need to add it to the API response or infer it.
        # For now, we display what we have.
        
        st.metric("Scam Detected", str(data.get("scamDetected", False)))
        
        st.subheader("Intelligence")
        st.json(data.get("extractedIntelligence", {}))
        
        st.subheader("Metrics")
        st.json(data.get("engagementMetrics", {}))
        
        if data.get("agentNotes"):
            st.warning(f"Agent Notes: {data['agentNotes']}")

# --- Main Chat Interface ---

# Display History
for msg in st.session_state.conversation_history:
    with st.chat_message(msg["role"]):
        st.write(msg["content"])

# Input for New Message
if prompt := st.chat_input("Send a scammer message..."):
    # 1. Display User Message
    st.session_state.conversation_history.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.write(prompt)

    # 2. Build API Payload
    # Construct conversation history format required by backend
    backend_history = []
    for m in st.session_state.conversation_history[:-1]: # Exclude current prompt, backend adds it? 
        # Actually api_contract says request includes 'message' (current) AND 'conversationHistory' (previous).
        sender = "scammer" if m["role"] == "user" else "agent"
        backend_history.append({
            "sender": sender,
            "text": m["content"],
            "timestamp": "2026-01-26T12:00:00Z" # Mock timestamp
        })

    payload = {
        "sessionId": st.session_state.session_id,
        "message": {
            "sender": "scammer",
            "text": prompt,
            "timestamp": "2026-01-26T12:00:00Z"
        },
        "conversationHistory": backend_history
    }

    # 3. Call Backend API
    try:
        response = requests.post(
            API_URL,
            json=payload,
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            resp_data = response.json()
            st.session_state.last_response_data = resp_data
            
            agent_reply = resp_data.get("agentReply", "")
            
            if agent_reply:
                st.session_state.conversation_history.append({"role": "assistant", "content": agent_reply})
                with st.chat_message("assistant"):
                    st.write(agent_reply)
            else:
                if resp_data.get("scamDetected"):
                     st.info("(Agent is observing... No reply yet)")
                else:
                     st.info("(System processing... No scam detected yet)")

        elif response.status_code == 409:
            st.error("Session Closed: The agent has exited the conversation.")
        else:
            st.error(f"API Error: {response.status_code} - {response.text}")
            
    except Exception as e:
        st.error(f"Connection Failed: {e}")

    # Force UI update for sidebar
    st.rerun()
