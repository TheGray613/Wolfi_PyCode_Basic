student_Data = {
    "name": "jason",
    "age": "20",
    "mark": "19"
}
for Information_student in student_Data:
    print (Information_student)

for Information_data_tuples in student_Data.items():
    print(Information_data_tuples)

for Information_data_just_keys in student_Data.keys():
    print(Information_data_just_keys)

for Information_data_just_values in student_Data.values():
    print(Information_data_just_values)

#tuple unpacking
for (key, values) in student_Data.items():
    print(key)
    print(values)

id_number = [("sara", 4455), ("jason", 9878), ("yaser", 23125)]
for (name, number) in id_number:
    print(f"{name}'s id number is {number}")
