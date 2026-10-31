"""Authenticated Streamlit chat UI. Run with: streamlit run app.py"""
import os, re, uuid
from datetime import datetime, timezone
import streamlit as st
from database.seed import seed
from database.db import connect
from config.settings import get_chat_model
from agent.graph import build_graph, run_agent
from rag.retrieval import PolicyRetriever
from memory.store import list_memories, save_memory, delete_memory
from memory.policies import classify_memory
from observability.tracing import write_trace
from observability.audit import list_audit
from security.auth import authenticate
from security.redaction import redact_sensitive
from security.authorization import authenticated_as
from security.approvals import request_email_change, pending_actions, decide_action

st.set_page_config(page_title="Student Support Agent",page_icon="🎓",layout="wide")
st.title("🎓 Intelligent Student Support Agent")
st.caption("Assignment 2 local demo. All student data is fictional.")
seed()
if "principal" not in st.session_state: st.session_state.principal=None
if not st.session_state.principal:
    st.subheader("Sign in")
    with st.form("login"):
        username=st.text_input("Username")
        password=st.text_input("Password",type="password")
        submit=st.form_submit_button("Sign in")
    if submit:
        principal=authenticate(username,password)
        if principal:
            with connect() as db:
                db.execute(
                    """
                    INSERT INTO login_history
                    (username, role, student_id, logged_in_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        principal.username,
                        principal.role,
                        principal.student_id,
                        datetime.now(timezone.utc).isoformat()
                    )   
                )

            st.session_state.principal = principal
            st.session_state.chat = []
            st.rerun()
        else: st.error("Sign-in failed.")
    st.info(
    "Student demo accounts: "
    "anaya / Anaya-Demo-2026!, "
    "rohan / Rohan-Demo-2026!, "
    "kiara / Kiara-Demo-2026!. "
    "Approver: approver / Approve-Demo-2026!"
    )
    st.stop()

principal=st.session_state.principal
if "session_id" not in st.session_state: st.session_state.session_id=str(uuid.uuid4())
with st.sidebar:
    st.success(f"Signed in: {principal.username} ({principal.role})")
    if st.button("Sign out"):
        st.session_state.principal=None; st.session_state.chat=[]; st.rerun()
    st.caption("Conversation session: "+st.session_state.session_id[:8])
    if st.button("New conversation session"):
        st.session_state.session_id=str(uuid.uuid4()); st.session_state.chat=[]; st.rerun()
    if principal.role=="student":
        st.subheader("Long-term memory")
        for m in list_memories(principal.student_id):
            c1,c2=st.columns([4,1]); c1.write(m['fact'])
            if c2.button("Delete",key=f"del-{m['memory_id']}"):
                delete_memory(principal.student_id,m['memory_id']); st.rerun()
        with st.expander("Save a stable preference or study fact"):
            fact=st.text_input("Fact")
            if st.button("Save memory") and fact:
                safe,_=redact_sensitive(fact); result=save_memory(principal.student_id,safe)
                st.info(result['reason']); st.rerun()

if principal.role=="approver":
    st.subheader("Pending sensitive changes")
    with authenticated_as(principal): actions=pending_actions()
    if not actions: st.info("No pending actions.")
    for action in actions:
        st.write(f"Action {action['action_id']} · {action['requester_id']} proposes contact email {action['proposed_value']}")
        a,b=st.columns(2)
        for label,decision,col in (("Approve",True,a),("Reject",False,b)):
            if col.button(label,key=f"{label}-{action['action_id']}"):
                with authenticated_as(principal): result=decide_action(action['action_id'],decision)
                st.success(result['message']); st.rerun()
else:
    with st.expander("Sensitive action: request contact email change"):
        new_email=st.text_input("New contact email")
        if st.button("Submit for approver review"):
            try:
                with authenticated_as(principal): result=request_email_change(principal.student_id,new_email,correlation_id=st.session_state.session_id)
                st.info(f"Pending approval · Action ID: {result['action_id']}")
            except (ValueError,PermissionError): st.error("This request could not be submitted. Check the email and try again.")

# --------------------------------------------------
# STUDENT RECORDS AND ACTIVITY DASHBOARD
# --------------------------------------------------
st.subheader("Student records and activity")

records_tab, email_tab, login_tab = st.tabs([
    "Student records",
    "Email-change history",
    "Login history"
])

# 1. Student records
with records_tab:
    with connect() as db:
        if principal.role == "approver":
            rows = db.execute("""
                SELECT student_id, display_name, programme, semester,
                       contact_email
                FROM students
                ORDER BY student_id
            """).fetchall()
        else:
            rows = db.execute("""
                SELECT student_id, display_name, programme, semester,
                       contact_email
                FROM students
                WHERE student_id = ?
            """, (principal.student_id,)).fetchall()

    if rows:
        st.dataframe(
            [dict(row) for row in rows],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No student records found.")

# 2. Email-change history
with email_tab:
    with connect() as db:
        if principal.role == "approver":
            history = db.execute("""
                SELECT action_id, requester_id, target_id,
                       proposed_value, status, created_at,
                       decided_at, approver_id
                FROM pending_actions
                ORDER BY created_at DESC
            """).fetchall()
        else:
            history = db.execute("""
                SELECT action_id, requester_id, target_id,
                       proposed_value, status, created_at,
                       decided_at, approver_id
                FROM pending_actions
                WHERE target_id = ? OR requester_id = ?
                ORDER BY created_at DESC
            """, (principal.student_id, principal.student_id)).fetchall()

    if history:
        st.dataframe(
            [dict(row) for row in history],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No email-change requests recorded yet.")

# 3. Login history
with login_tab:
    with connect() as db:
        if principal.role == "approver":
            logins = db.execute("""
                SELECT username, role, student_id, logged_in_at
                FROM login_history
                ORDER BY logged_in_at DESC
            """).fetchall()
        else:
            logins = db.execute("""
                SELECT username, role, student_id, logged_in_at
                FROM login_history
                WHERE student_id = ?
                ORDER BY logged_in_at DESC
            """, (principal.student_id,)).fetchall()

    if logins:
        st.dataframe(
            [dict(row) for row in logins],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No login history recorded yet.")


st.subheader("Student support chat")
if "chat" not in st.session_state: st.session_state.chat=[]
for item in st.session_state.chat:
    with st.chat_message(item['role']): st.markdown(item['content'])
question=st.chat_input("Ask about fees, scholarships, courses, policy, or support") if principal.role=="student" else None
if question:
    safe_question,secret_detected=redact_sensitive(question)
    st.session_state.chat.append({"role":"user","content":safe_question})
    with st.chat_message("user"): st.markdown(safe_question)
    with st.chat_message("assistant"):
        try:
            allowed,_=classify_memory(safe_question)
            if allowed: save_memory(principal.student_id,safe_question)
            model=get_chat_model(); graph=build_graph(model,PolicyRetriever(os.getenv("STUDENT_AGENT_POLICY","rag/sample_handbook.md")))
            result=run_agent(graph,safe_question,principal.student_id,st.session_state.session_id,principal)
            if secret_detected and "excluded from saved history" not in result['answer']:
                result['answer'] += "\n\nFor your safety, sensitive credentials were excluded from saved history and memory."
            st.markdown(result['answer']); st.session_state.chat.append({"role":"assistant","content":result['answer']})
            write_trace(result['trace'],safe_question,result['answer'])
            with st.expander("Run trace and policy evidence"):
                st.json(result['trace'])
                for item in result['policy']: st.markdown(f"**{item['chunk_id']}** · {item['source']}\n\n{item['text']}")
        except Exception:
            st.error("The agent could not complete this request. Check model availability and configuration, then retry.")

with st.expander("Security audit (evaluator)"):
    st.json(list_audit(100))
