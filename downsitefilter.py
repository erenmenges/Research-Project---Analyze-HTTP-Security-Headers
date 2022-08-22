from pandas import *
import csv

with open('/Users/erenmenges/Desktop/KODLAMA/VScode/Python/output_nonfederal1.csv', newline='') as f:
    reader = csv.reader(f)
    data = list(reader)


def checktwos(row):
    for number in row:
        if number == "2":
            return True

offlines = []

for row in data:
    if checktwos(row) == True:
        offlines.append(data.index(row))
        
count = 0
for index in offlines:
    del data[index - count]
    count = count + 1

for row in data:
    with open('/Users/erenmenges/Desktop/KODLAMA/VScode/Python/up_nonfederal1.csv', 'a') as f:
        writer2 = csv.writer(f)
        writer2.writerow(row)




        