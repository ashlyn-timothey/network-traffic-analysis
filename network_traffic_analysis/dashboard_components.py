"""Native Streamlit renderers for dashboard summaries and investigation records."""


def _display_value(value):
    return "Not available" if value is None else str(value)


def render_count_rows(ui, entries, value_label):
    """Render label/count pairs without dataframe-based Streamlit elements."""
    for label, value in entries:
        with ui.container(border=True):
            label_column, value_column = ui.columns([3, 1])
            label_column.text(_display_value(label))
            value_column.metric(value_label, value)


def render_labeled_fields(ui, fields, columns_per_row=3):
    """Render scalar label/value pairs in compact native Streamlit columns."""
    for offset in range(0, len(fields), columns_per_row):
        row = fields[offset : offset + columns_per_row]
        with ui.container(border=True):
            columns = ui.columns(len(row))
            for column, (label, value) in zip(columns, row):
                column.caption(label)
                column.text(_display_value(value))


def render_investigation_cards(
    ui,
    investigations,
    *,
    include_upload_time=False,
    include_id=False,
):
    """Render saved investigations as readable, responsive cards."""
    for item in investigations:
        with ui.container(border=True):
            name_column, status_column = ui.columns([3, 1])
            name_column.text(_display_value(item.get("name")))
            status_column.metric("Status", _display_value(item.get("status")))
            ui.text(f"Capture: {_display_value(item.get('capture_filename'))}")

            fields = [
                ("Packets", item.get("packet_count")),
                ("Created (UTC)", item.get("created_at")),
                ("Updated (UTC)", item.get("updated_at")),
            ]
            if include_upload_time:
                fields.insert(1, ("Upload received (UTC)", item.get("uploaded_at")))
            render_labeled_fields(ui, fields)

            if include_id:
                ui.caption(f"Investigation ID: {_display_value(item.get('id'))}")


def render_timeline_cards(ui, events, timestamp_formatter):
    """Render evidence-derived timeline entries without dataframe conversion."""
    for event in events:
        with ui.container(border=True):
            time_column, detection_column, address_column = ui.columns([2, 2, 3])
            time_column.metric(
                "Capture time (UTC)", timestamp_formatter(event.get("timestamp"))
            )
            time_column.text(
                f"Packet: {_display_value(event.get('packet_number'))}"
            )

            detection_column.text(_display_value(event.get("finding_type")))
            detection_column.metric(
                "Severity", _display_value(event.get("severity"))
            )

            address_column.text(
                f"Source IP: {_display_value(event.get('source_ip'))}"
            )
            address_column.text(
                f"Destination IP: {_display_value(event.get('destination_ip'))}"
            )
