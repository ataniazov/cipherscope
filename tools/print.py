def print_matrix(matrix, indent=8):
    assert isinstance(matrix, list), f"\"{matrix}\" is not matrix!"
    rows = len(matrix)
    if rows > 0:
        assert all(isinstance(row, list)
                   for row in matrix), f"\"{matrix}\" is not matrix!"
        cols = len(matrix[0])
        if cols == 0:
            return
    else:
        return

    buf = ""

    for row in range(rows):
        buf += " " * indent
        buf += "+----" * cols + "+" * (1 if cols > 0 else 0) + "\n"

        buf += " " * indent

        for col in range(cols):
            buf += "| {:02X} ".format(matrix[row][col])
        buf += "|\n"

    buf += " " * indent
    buf += "+----" * cols + "+" * (1 if cols > 0 else 0) + "\n"

    print(buf, end="")


def print_2_matrix(matrix_1, matrix_2, indent=8, gap=4):
    assert isinstance(matrix_1, list), f"\"{matrix_1}\" is not matrix!"
    rows_m1 = len(matrix_1)
    if rows_m1 > 0:
        assert all(isinstance(row, list)
                   for row in matrix_1), f"\"{matrix_1}\" is not matrix!"
        cols_m1 = len(matrix_1[0])
    else:
        cols_m1 = 0
        gap = 0

    assert isinstance(matrix_2, list), f"\"{matrix_2}\" is not matrix!"
    rows_m2 = len(matrix_2)
    if rows_m2 > 0:
        assert all(isinstance(row, list)
                   for row in matrix_2), f"\"{matrix_2}\" is not matrix!"
        cols_m2 = len(matrix_2[0])
    else:
        cols_m2 = 0
        gap = 0

    rows = rows_m1 if rows_m1 > rows_m2 else rows_m2

    if rows == 0:
        return

    buf = ""

    for row in range(rows):
        buf += " " * indent

        if rows_m1 >= row:
            buf += "+----" * cols_m1 + "+" * \
                (1 if cols_m1 > 0 else 0) + " " * gap
        else:
            buf += " " * 5 * cols_m1 + " " * \
                (1 if cols_m1 > 0 else 0) + " " * gap

        if rows_m2 >= row:
            buf += "+----" * cols_m2 + "+" * (1 if cols_m2 > 0 else 0)
        buf += "\n"

        buf += " " * indent
        if row < rows_m1:
            for col in range(cols_m1):
                buf += "| {:02X} ".format(matrix_1[row][col])
            buf += "|" + " " * gap
        else:
            buf += " " * 5 * cols_m1 + " " * \
                (1 if cols_m1 > 0 else 0) + " " * gap

        if row < rows_m2:
            for col in range(cols_m2):
                buf += "| {:02X} ".format(matrix_2[row][col])
            buf += "|"
        buf += "\n"

    buf += " " * indent

    if rows_m1 >= rows:
        buf += "+----" * cols_m1 + "+" * (1 if cols_m1 > 0 else 0) + " " * gap
    else:
        buf += " " * 5 * cols_m1 + " " * (1 if cols_m1 > 0 else 0) + " " * gap

    if rows_m2 >= rows:
        buf += "+----" * cols_m2 + "+" * (1 if cols_m2 > 0 else 0)

    print(buf + "\n", end="")


def print_array(array, indent=8):
    assert isinstance(array, list), f"\"{array}\" is not array!"
    length = len(array)
    if length == 0:
        return

    buf = " " * indent
    buf += "+----" * length + "+" * (1 if length > 0 else 0) + "\n"

    buf += " " * indent
    for index in range(length):
        buf += "| {:02X} ".format(array[index])
    buf += "|\n"

    buf += " " * indent
    buf += "+----" * length + "+" * (1 if length > 0 else 0) + "\n"

    print(buf, end="")


def print_2_array_up_down(array_1, array_2, indent=8):
    assert isinstance(array_1, list), f"\"{array_1}\" is not array!"
    length_a1 = len(array_1)

    assert isinstance(array_2, list), f"\"{array_2}\" is not array!"
    length_a2 = len(array_2)

    length = length_a1 if length_a1 > length_a2 else length_a2

    if length == 0:
        return

    buf = ""

    if length_a1 > 0:
        buf += " " * indent
        buf += "+----" * length_a1 + "+" * (1 if length_a1 > 0 else 0) + "\n"

        buf += " " * indent
        for index in range(length_a1):
            buf += "| {:02X} ".format(array_1[index])
        buf += "|\n"

    buf += " " * indent
    buf += "+----" * length + "+" * (1 if length > 0 else 0) + "\n"

    if length_a2 > 0:
        buf += " " * indent
        for index in range(length_a2):
            buf += "| {:02X} ".format(array_2[index])
        buf += "|\n"

        buf += " " * indent
        buf += "+----" * length_a2 + "+" * (1 if length_a2 > 0 else 0) + "\n"

    print(buf, end="")


def print_2_array_left_right(array_1, array_2, indent=8, gap=4):
    assert isinstance(array_1, list), f"\"{array_1}\" is not array!"
    length_a1 = len(array_1)

    assert isinstance(array_2, list), f"\"{array_2}\" is not array!"
    length_a2 = len(array_2)

    if length_a1 == 0 and length_a2 == 0:
        return

    buf = " " * indent
    if length_a1 > 0:
        buf += "+----" * length_a1 + "+" * (1 if length_a1 > 0 else 0)
        buf += " " * gap

    if length_a2 > 0:
        buf += "+----" * length_a2 + "+" * (1 if length_a2 > 0 else 0)
    buf += "\n"

    buf += " " * indent

    if length_a1 > 0:
        for index in range(length_a1):
            buf += "| {:02X} ".format(array_1[index])
        buf += "|"
        buf += " " * gap

    if length_a2 > 0:
        for index in range(length_a2):
            buf += "| {:02X} ".format(array_2[index])
        buf += "|"

    buf += "\n"

    buf += " " * indent
    if length_a1 > 0:
        buf += "+----" * length_a1 + "+" * (1 if length_a1 > 0 else 0)
        buf += " " * gap

    if length_a2 > 0:
        buf += "+----" * length_a2 + "+" * (1 if length_a2 > 0 else 0)

    print(buf + "\n", end="")


def print_msg_box(msg, indent=0, align=1, width=None, title=None):
    lines = msg.split("\n")
    space = " " * align

    if not width:
        width = max(map(len, lines))

    buf = f"{' ' * indent}+{'-' * (width + align * 2)}+\n"

    if title:
        buf += f"{' ' * indent}|{space}{title:<{width}}{space}|\n"
        buf += f"{' ' * indent}|{space}{'-' * len(title):<{width}}{space}|\n"

    buf += "".join([f"{' ' * indent}|{space}{line:<{width}}{space}|\n" for line in lines])

    buf += f"{' ' * indent}+{'-' * (width + align * 2)}+\n"

    print(buf, end="")


def print_array_bit_diff(array_1, array_2, indent=4):
    assert isinstance(array_1, list), f"\"{array_1}\" is not array!"
    length_a1 = len(array_1)

    assert isinstance(array_2, list), f"\"{array_2}\" is not array!"
    length_a2 = len(array_2)

    if length_a1 > length_a2:
        length_max = length_a1
        length_min = length_a2
    else:
        length_min = length_a1
        length_max = length_a2

    if length_max == 0:
        return

    buf = " " * (indent-1)
    buf += "+--------" * length_max + "+" * (1 if length_max > 0 else 0) + "\n"

    if length_a1 > 0:
        buf += " " * indent
        for index in range(length_a1):
            buf += "{:08b} ".format(array_1[index])
        buf += "\n"

    if length_a2 > 0:
        buf += " " * indent
        for index in range(length_a2):
            buf += "{:08b} ".format(array_2[index])
        buf += "\n"

    buf += " " * (indent-1)
    buf += "+--------" * length_max + "+" * (1 if length_max > 0 else 0) + "\n"

    count = 0
    buf += " " * indent
    for index in range(length_min):
        diff = array_1[index] ^ array_2[index]
        while diff:
            count += diff & 1
            diff >>= 1
        buf += "{:08b} ".format(array_1[index] ^ array_2[index]
                                ).replace("0", "-").replace("1", "X")
    buf += "\n"

    buf += " " * (indent-1)
    buf += "+--------" * length_max + "+" * (1 if length_max > 0 else 0) + "\n"

    print(buf+"\n", end="")

    print_msg_box("Bit difference: {}".format(count), indent-1)


matrix_1 = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]]
matrix_2 = [[17, 18, 19, 20], [21, 22, 23, 24],
            [25, 26, 27, 28], [29, 30, 31, 32]]

array_1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
array_2 = [15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29]

print_matrix(matrix_1)

print("\n")

print_2_matrix(matrix_1, matrix_2, 4)

print("\n")

print_2_array_up_down(array_1, array_2, 4)

print("\n")

print_2_array_left_right(array_1, array_2, 0, 2)

print("\n")

print_array_bit_diff(array_1, array_2, 2)

print("\n")

print_msg_box("Message Box", indent=4, align=5)
