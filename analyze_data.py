import csv

with open('/Users/shashvatgarg/Desktop/Shashvat_Garg/Intern_IITR/SecureChat/shared/data.csv', 'r', newline='') as file:
    reader = csv.reader(file)
    data1 = list(reader)
    time = []
    data = []
    # Taking Header into account
    if data1 and data1[0]:
        data1 = data1[1:]  # Skip the header row
    else:
        print("No data found in the file.")
        exit()
    for row in data1:
        if row:
            time.append(float(row[0]))
            data.append(row[1])
    print("Time:", time)
    print("Data:", data)
    file.close()

print("Efficiency:", len(data)/(time[-1]-time[0]))