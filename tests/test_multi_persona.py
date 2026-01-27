import os
import random
# Mock environment to enable LLM path
os.environ["USE_LLM"] = "true"
os.environ["LLM_API_KEY"] = "dummy"

from app.core.session import SessionManager
from app.agent.reply_service import AgentReplyService

def run_test():
    session_manager = SessionManager()
    reply_service = AgentReplyService()
    
    # Force the service to use LLM settings
    reply_service.use_llm = True
    reply_service.llm_api_key = "dummy"

    sessions = ["session_1", "session_2", "session_3"]
    results = {}

    print("--- Starting Multi-Persona Consistency Test ---")

    for sid in sessions:
        # 1. Create session (should assign random persona)
        session = session_manager.get_or_create_session(sid)
        persona = session.agentPersona
        results[sid] = {"persona": persona, "replies": []}
        
        print(f"Session {sid}: Assigned Persona = {persona}")
        
        # 2. Simulate turns
        states = ["CONFUSED", "TRUST_BUILDING", "INFORMATION_EXTRACTION", "EXIT"]
        
        # Force states for testing (normally AgentController does this)
        for state in states:
            session.agentState = state
            
            # Generate reply
            reply = reply_service.generate_reply(
                agent_state=state,
                scammer_message="Urgent action required",
                persona_name=persona
            )
            
            results[sid]["replies"].append(reply)
            
            # Verify persona hasn't changed
            if session.agentPersona != persona:
                print(f"VIOLATION: Persona changed from {persona} to {session.agentPersona} in session {sid}")
                return

    print("\n--- Results Analysis ---")
    
    # Check consistency
    consistent = True
    for sid, data in results.items():
        print(f"\n{sid} ({data['persona']}):")
        for r in data['replies']:
            print(f"  - {r}")
            if "[LLM-" not in r:
                 print("  VIOLATION: Did not use LLM path")
                 consistent = False

    if consistent:
        print("\nMulti-persona system behaves correctly (Architecturally)")
    else:
        print("\nPersona consistency violation detected")

if __name__ == "__main__":
    run_test()
