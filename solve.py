n = 100
sum = 0
left = 0
right = 0
temp = 0
while n > 0:
    left = left + n
    temp = n * n
    right = right + temp
    n = n - 1
left = left * left
result = left - right
print(result)