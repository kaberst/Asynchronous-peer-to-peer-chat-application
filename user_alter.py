import json

# Load the existing data from the JSON file
with open('users.json', 'r') as f:
    existing_data = json.load(f)

# Get the user input
username = input("Enter username: ")
password = input("Enter password: ")
port = int(input("Enter port: "))
ip = input("Enter IP address: ")

# Add the new data to the existing data
new_data = {'username': username, 'password': password, 'port': port, 'ip': ip}
existing_data.append(new_data)

# Serialize the updated data and store it in the JSON file
with open('users.json', 'w') as f:
    json.dump(existing_data, f, indent=4)
