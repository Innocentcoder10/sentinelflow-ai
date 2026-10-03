import json

with open("data/alerts.json", "r") as file:
    alerts = json.load(file)

print("Number of alerts:", len(alerts))

for alert in alerts:
    print(
        alert["alert_id"],
        "-",
        alert["case_type"],
        "-",
        alert["alert_name"]
    )