"""
Displays chronological timeline of all forensic events from correlation report
"""

import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Page configuration
st.set_page_config(
    page_title="Event Timeline",
    page_icon="📅",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .timeline-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .event-card {
        background: #f8f9fa;
        padding: 0.75rem;
        border-radius: 0.5rem;
        border-left: 3px solid #3498db;
        margin: 0.25rem 0;
    }
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="timeline-header"><h1 style="margin:0;">📅 Event Timeline</h1><p style="margin:0;">Chronological reconstruction of system activity</p></div>', unsafe_allow_html=True)

# ============================================================
# DATA LOADING
# ============================================================

@st.cache_data
def load_timeline_data():
    """
    Load and flatten timeline data from correlation report
    
    Returns:
        DataFrame with timeline events
    """
    correlation_path = "report/correlation.json"
    
    if not os.path.exists(correlation_path):
        return None
    
    try:
        with open(correlation_path, 'r', encoding='utf-8') as f:
            correlation = json.load(f)
        
        # Flatten events from all processes
        all_events = []
        
        for process_key, events in correlation.items():
            if isinstance(events, list):
                for event in events:
                    # Add process context
                    event_copy = event.copy()
                    event_copy['process_key'] = process_key
                    all_events.append(event_copy)
        
        if not all_events:
            return None
        
        # Create DataFrame
        df = pd.DataFrame(all_events)
        
        # Parse timestamps with timezone handling
        def safe_parse_time(t):
            """Parse timestamp and normalize to timezone-naive"""
            if pd.isna(t) or not t:
                return pd.NaT
            
            try:
                if isinstance(t, str):
                    # Remove 'Z' suffix (UTC indicator)
                    t = t.replace('Z', '')
                    
                    # Remove timezone info if present (e.g., +00:00)
                    if '+' in t:
                        t = t.split('+')[0]
                    if 'T' in t and len(t.split('T')) > 1:
                        # ISO format
                        parsed = pd.to_datetime(t, errors='coerce')
                    else:
                        # Other formats
                        parsed = pd.to_datetime(t, errors='coerce')
                    
                    # Convert to timezone-naive if timezone-aware
                    if parsed is not pd.NaT:
                        if hasattr(parsed, 'tz') and parsed.tz is not None:
                            parsed = parsed.tz_localize(None)
                    
                    return parsed
                
                elif isinstance(t, (int, float)):
                    # Unix timestamp
                    return pd.to_datetime(t, unit='s', errors='coerce')
                
                else:
                    # Already datetime
                    parsed = pd.to_datetime(t, errors='coerce')
                    if parsed is not pd.NaT:
                        if hasattr(parsed, 'tz') and parsed.tz is not None:
                            parsed = parsed.tz_localize(None)
                    return parsed
            
            except Exception as e:
                # If all else fails, return NaT
                return pd.NaT
        
        df['timestamp'] = df['time'].apply(safe_parse_time)
        
        # Remove events with no valid timestamp
        df = df.dropna(subset=['timestamp'])
        
        if df.empty:
            return None
        
        # Ensure all timestamps are timezone-naive
        if hasattr(df['timestamp'].dtype, 'tz') and df['timestamp'].dtype.tz is not None:
            df['timestamp'] = df['timestamp'].dt.tz_localize(None)
        
        # Sort by time
        df = df.sort_values('timestamp')
        
        return df
    
    except Exception as e:
        st.error(f"Error loading timeline data: {e}")
        import traceback
        st.code(traceback.format_exc())
        return None


def get_event_color(tag):
    """Assign color based on event tag"""
    color_map = {
        'PROCESS-CREATE': '#3498db',
        'NETWORK': '#e74c3c',
        'FILE-CREATE': '#2ecc71',
        'FILE-DELETE': '#e67e22',
        'SNAPSHOT-ADD': '#1abc9c',
        'SNAPSHOT-MOD': '#f39c12',
        'SNAPSHOT-DEL': '#c0392b',
        'MEMORY-PROCESS': '#9b59b6',
        'CLOUD': '#16a085',
        'DNS-QUERY': '#34495e',
    }
    
    # Match by prefix if exact match not found
    if tag:
        tag_upper = str(tag).upper()
        for key, color in color_map.items():
            if key in tag_upper:
                return color
    
    return '#95a5a6'  # Default gray


# ============================================================
# MAIN INTERFACE
# ============================================================

# Load data
df = load_timeline_data()

if df is None or df.empty:
    st.warning("⚠️ No timeline data available.")
    st.info("""
    **How to fix:**
    1. Run the forensic pipeline from the main dashboard
    2. Enable at least one data source (Sysmon or Snapshots)
    3. Ensure correlation.json was generated in the report/ directory
    """)
    
    # Check if file exists
    if os.path.exists("report/correlation.json"):
        st.warning("correlation.json exists but contains no parseable events")
    else:
        st.error("correlation.json not found. Run the pipeline first.")
    
    st.stop()

# ============================================================
# INFO BOX
# ============================================================
st.info("""
**📖 How to use this timeline:**
- **Filter** by source, tag, or process to focus on specific activities
- **Time slider** to zoom into specific time ranges
- **Look for patterns:** Burst activity often indicates ransomware encryption
- **Export** filtered data for external analysis or reporting
""")

st.markdown("---")

# ============================================================
# SIDEBAR FILTERS
# ============================================================

st.sidebar.markdown("## ⚙️ Timeline Filters")

# Source filter
sources = ['All'] + sorted(df['source'].dropna().unique().tolist())
selected_source = st.sidebar.selectbox(
    "📁 Event Source",
    sources,
    help="Filter by data source (Sysmon, Snapshot, Cloud, etc.)"
)

# Tag filter
tags = ['All'] + sorted(df['tag'].dropna().unique().tolist())
selected_tag = st.sidebar.selectbox(
    "🏷️ Event Tag",
    tags,
    help="Filter by event type"
)

# Time range filter
min_time = df['timestamp'].min()
max_time = df['timestamp'].max()

# Convert to datetime for slider (ensuring timezone-naive)
if hasattr(min_time, 'tz') and min_time.tz is not None:
    min_time = min_time.tz_localize(None)
if hasattr(max_time, 'tz') and max_time.tz is not None:
    max_time = max_time.tz_localize(None)

# Create timezone-naive datetime objects for slider
min_time_dt = min_time.to_pydatetime() if isinstance(min_time, pd.Timestamp) else min_time
max_time_dt = max_time.to_pydatetime() if isinstance(max_time, pd.Timestamp) else max_time

time_range = st.sidebar.slider(
    "⏰ Time Range",
    min_value=min_time_dt,
    max_value=max_time_dt,
    value=(min_time_dt, max_time_dt),
    format="YYYY-MM-DD HH:mm",
    help="Adjust to zoom into specific time period"
)

# Process filter
processes = ['All'] + sorted(df['process_key'].dropna().unique().tolist())
selected_process = st.sidebar.selectbox(
    "⚙️ Process",
    processes,
    help="Filter by specific process"
)

# Apply filters
filtered_df = df.copy()

if selected_source != 'All':
    filtered_df = filtered_df[filtered_df['source'] == selected_source]

if selected_tag != 'All':
    filtered_df = filtered_df[filtered_df['tag'] == selected_tag]

if selected_process != 'All':
    filtered_df = filtered_df[filtered_df['process_key'] == selected_process]

# Time range filter (convert slider values to timezone-naive pandas Timestamps)
time_start = pd.Timestamp(time_range[0])
time_end = pd.Timestamp(time_range[1])

filtered_df = filtered_df[
    (filtered_df['timestamp'] >= time_start) &
    (filtered_df['timestamp'] <= time_end)
]

st.sidebar.markdown("---")
st.sidebar.markdown("### 📊 Event Count")
st.sidebar.metric("Total Events", f"{len(df):,}")
st.sidebar.metric("Filtered Events", f"{len(filtered_df):,}")

if len(filtered_df) < len(df):
    percentage = (len(filtered_df) / len(df) * 100)
    st.sidebar.caption(f"{percentage:.1f}% of total events")

# ============================================================
# SUMMARY METRICS
# ============================================================

st.markdown("## 📊 Timeline Summary")

col1, col2, col3, col4 = st.columns(4)

with col1:
    delta_text = f"{len(filtered_df) - len(df)}" if len(filtered_df) != len(df) else None
    st.metric(
        "Events Shown",
        f"{len(filtered_df):,}",
        delta=delta_text,
        help="Number of events matching current filters"
    )

with col2:
    unique_processes = filtered_df['process_key'].nunique()
    st.metric(
        "Unique Processes",
        unique_processes,
        help="Number of distinct processes in filtered view"
    )

with col3:
    if not filtered_df.empty:
        time_span = (filtered_df['timestamp'].max() - filtered_df['timestamp'].min())
        time_span_hours = time_span.total_seconds() / 3600
        
        if time_span_hours < 1:
            time_str = f"{time_span.total_seconds()/60:.0f} min"
        elif time_span_hours < 24:
            time_str = f"{time_span_hours:.1f} hrs"
        else:
            time_str = f"{time_span_hours/24:.1f} days"
        
        st.metric(
            "Time Span",
            time_str,
            help="Duration covered by filtered events"
        )
    else:
        st.metric("Time Span", "N/A")

with col4:
    unique_sources = filtered_df['source'].nunique()
    st.metric(
        "Data Sources",
        unique_sources,
        help="Number of different data sources"
    )

st.markdown("---")

# ============================================================
# INTERPRETATION GUIDE
# ============================================================
with st.expander("💡 Reading the Timeline", expanded=False):
    st.markdown("""
    **What to look for:**
    
    🔴 **Suspicious Patterns:**
    - Burst of file modifications in short time (potential encryption)
    - Process creation followed immediately by network connections (malware download)
    - Mass file deletions (data destruction)
    - Unusual parent-child process relationships (e.g., Word spawning PowerShell)
    
    🟡 **Normal Patterns:**
    - Gradual file changes over time (normal work)
    - Known processes with expected network activity (updates, cloud sync)
    - Regular scheduled tasks
    
    📊 **Chart Interpretation:**
    - **Spikes** = Burst activity (investigate further)
    - **Flat lines** = Steady activity (usually normal)
    - **Multiple event types clustered** = Complex attack chain
    """)

# ============================================================
# TIMELINE VISUALIZATION
# ============================================================

st.markdown("## 📈 Event Timeline Chart")

if not filtered_df.empty:
    # Create time-based aggregation
    filtered_df['hour'] = filtered_df['timestamp'].dt.floor('H')
    event_counts = filtered_df.groupby(['hour', 'tag']).size().reset_index(name='count')
    
    # Create chart
    chart_data = event_counts.pivot(index='hour', columns='tag', values='count').fillna(0)
    
    if not chart_data.empty:
        st.area_chart(chart_data, use_container_width=True, height=400)
        st.caption("📊 Events aggregated by hour and categorized by event type")
    else:
        st.info("Not enough data points to create chart")
else:
    st.warning("⚠️ No events match the current filters. Try adjusting your filters.")

st.markdown("---")

# ============================================================
# EVENT LIST
# ============================================================

st.markdown("## 📋 Detailed Event List")

# Display options
col1, col2 = st.columns(2)

with col1:
    show_raw = st.checkbox("Show raw event data", value=False, help="Display full JSON for each event")

with col2:
    max_details_length = st.slider(
        "Details preview length",
        min_value=50,
        max_value=500,
        value=150,
        help="Truncate long event descriptions"
    )

if not filtered_df.empty:
    # Create display dataframe
    display_cols = ['timestamp', 'source', 'tag', 'name', 'details']
    
    # Add PID if available
    if 'pid' in filtered_df.columns and filtered_df['pid'].notna().any():
        display_cols.insert(4, 'pid')
    
    display_df = filtered_df[display_cols].copy()
    
    # Truncate details
    display_df['details'] = display_df['details'].apply(
        lambda x: str(x)[:max_details_length] + "..." if len(str(x)) > max_details_length else str(x)
    )
    
    # Format timestamp
    display_df['timestamp'] = display_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
    
    # Display with pagination
    events_per_page = 50
    total_pages = (len(display_df) - 1) // events_per_page + 1
    
    if total_pages > 1:
        col1, col2, col3 = st.columns([2, 1, 2])
        with col2:
            page = st.number_input(
                "Page",
                min_value=1,
                max_value=total_pages,
                value=1,
                help=f"Total {total_pages} pages ({events_per_page} events per page)"
            )
        
        start_idx = (page - 1) * events_per_page
        end_idx = start_idx + events_per_page
        page_df = display_df.iloc[start_idx:end_idx]
        
        st.caption(f"Page {page} of {total_pages} | Showing events {start_idx + 1}-{min(end_idx, len(display_df))} of {len(display_df):,}")
    else:
        page_df = display_df
        st.caption(f"Showing all {len(display_df):,} events")
    
    # Display table
    st.dataframe(
        page_df,
        use_container_width=True,
        hide_index=True,
        height=500
    )
    
    # ========================================
    # RAW EVENT DETAILS
    # ========================================
    if show_raw and not filtered_df.empty:
        st.markdown("---")
        st.markdown("### 🔍 Raw Event Details")
        
        selected_idx = st.number_input(
            "Select Event Index (from filtered list)",
            min_value=0,
            max_value=len(filtered_df) - 1,
            value=0,
            help="View complete raw data for a specific event"
        )
        
        if selected_idx < len(filtered_df):
            selected_event = filtered_df.iloc[selected_idx]
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Event Metadata:**")
                st.json({
                    "timestamp": str(selected_event['timestamp']),
                    "source": selected_event.get('source', 'N/A'),
                    "tag": selected_event.get('tag', 'N/A'),
                    "name": selected_event.get('name', 'N/A'),
                    "pid": str(selected_event.get('pid', 'N/A')),
                    "process_key": selected_event.get('process_key', 'N/A')
                })
            
            with col2:
                st.markdown("**Raw Event Data:**")
                if 'raw' in selected_event and selected_event['raw']:
                    st.json(selected_event['raw'])
                else:
                    st.info("No raw data available for this event")

else:
    st.warning("⚠️ No events to display. Adjust your filters to show events.")

# ============================================================
# EXPORT
# ============================================================

st.markdown("---")
st.markdown("## 💾 Export Timeline Data")

col1, col2 = st.columns(2)

with col1:
    if st.button("📥 Export as CSV", use_container_width=True, help="Download filtered events as CSV"):
        if not filtered_df.empty:
            # Prepare export data
            export_df = filtered_df.copy()
            export_df['timestamp'] = export_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
            
            csv = export_df.to_csv(index=False)
            
            st.download_button(
                label="⬇️ Download CSV File",
                data=csv,
                file_name=f"timeline_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        else:
            st.warning("No data to export")

with col2:
    if st.button("📥 Export as JSON", use_container_width=True, help="Download filtered events as JSON"):
        if not filtered_df.empty:
            # Prepare export data
            export_df = filtered_df.copy()
            export_df['timestamp'] = export_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
            
            json_data = export_df.to_json(orient='records', indent=2, date_format='iso')
            
            st.download_button(
                label="⬇️ Download JSON File",
                data=json_data,
                file_name=f"timeline_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
        else:
            st.warning("No data to export")

# ============================================================
# FOOTER
# ============================================================

st.markdown("---")
col1, col2 = st.columns(2)

with col1:
    st.caption("📅 Event Timeline Dashboard")
    st.caption("Unified Digital Forensic Framework")

with col2:
    if not filtered_df.empty:
        st.caption(f"📊 Analyzing {len(filtered_df):,} events")
        st.caption(f"⏰ From {filtered_df['timestamp'].min().strftime('%Y-%m-%d %H:%M')} to {filtered_df['timestamp'].max().strftime('%Y-%m-%d %H:%M')}")