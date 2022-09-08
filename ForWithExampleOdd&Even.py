my_numbers = [23, 45, 67, 93]
print ("you're first,second,third and fourth number is {} {} {} {}".format("23", "45", "67", "93"))
print(my_numbers[0:4])

for numbers in my_numbers:
    print(numbers)
    if numbers % 2 == 0:
        print ("this numbers is even", numbers)
    else:
        print ("This number is ODD", numbers) 
