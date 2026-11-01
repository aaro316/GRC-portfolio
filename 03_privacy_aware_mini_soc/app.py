
import streamlit as st
import pandas as pd

import database
import detector

st.set_page_config(
    page_title="Privacy-Aware Mini SOC",
    page_icon="🛡️",
    layout="wide"
)

st.title("Privacy-Aware Mini SOC")
st.caption("Security Event Monitoring and Incident Investigation")

# Initialize database and process events
database.init_db()

events = detector.load_events()
detected_alerts = detector.detect_suspicious_logins(events)
database.save_alerts(detected_alerts)

alerts = database.get_alerts()

# Summary metrics
total_events = len(events)
total_alerts = len(alerts)
open_alerts = sum(a["status"] == "Open" for a in alerts)
high_alerts = sum(a["severity"] == "High" for a in alerts)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Events Processed", total_events)
col2.metric("Total Alerts", total_alerts)
col3.metric("Open Alerts", open_alerts)
col4.metric("High Severity", high_alerts)

st.divider()

# Alert filters
st.subheader("Security Alerts")

filter_col1, filter_col2 = st.columns(2)

with filter_col1:
    severity_filter = st.selectbox(
        "Filter by severity",
        ["All", "High", "Medium", "Low"]
    )

with filter_col2:
    status_filter = st.selectbox(
        "Filter by status",
        ["All", "Open", "Investigating", "Resolved"]
    )

filtered_alerts = [
    alert for alert in alerts
    if (
        severity_filter == "All"
        or alert["severity"] == severity_filter
    )
    and (
        status_filter == "All"
        or alert["status"] == status_filter
    )
]

if filtered_alerts:
    display_columns = [
        "rule",
        "severity",
        "timestamp",
        "source_ip",
        "username",
        "description",
        "status"
    ]

    st.dataframe(
        pd.DataFrame(filtered_alerts)[display_columns],
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No alerts match the selected filters.")

st.divider()

# Investigation management
st.subheader("Update Investigation Status")

if alerts:
    alert_options = {
        f'{a["rule"]} | {a["username"]} | {a["timestamp"]}': a
        for a in alerts
    }

    selected_label = st.selectbox(
        "Select an alert",
        list(alert_options.keys())
    )

    selected_alert = alert_options[selected_label]

    statuses = ["Open", "Investigating", "Resolved"]

    new_status = st.selectbox(
        "New status",
        statuses,
        index=statuses.index(selected_alert["status"])
    )

    if st.button("Save status"):
        updated = database.update_alert_status(
            selected_alert["alert_id"],
            new_status
        )

        if updated:
            st.success("Investigation status updated.")
            st.rerun()
        else:
            st.error("Could not update the selected alert.")

st.divider()

# Alert distribution
st.subheader("Alerts by Detection Rule")

if alerts:
    distribution = (
        pd.DataFrame(alerts)["rule"]
        .value_counts()
        .rename_axis("Detection Rule")
        .reset_index(name="Alert Count")
    )

    st.bar_chart(
        distribution,
        x="Detection Rule",
        y="Alert Count"
    )
else:
    st.info("No alerts are available to chart.")

# Original security events
with st.expander("View source security events"):
    st.dataframe(
        pd.DataFrame(events),
        use_container_width=True,
        hide_index=True
    )
