def underscore_to_camelcase(underscore_str):
    """
    将下划线命名转换为驼峰命名
    :param underscore_str: 下划线命名的字符串，如 'hello_world'
    :return: 驼峰命名的字符串，如 'helloWorld'
    """
    parts = underscore_str.split("_")
    return parts[0] + "".join(word.capitalize() for word in parts[1:])


def camelcase_to_underscore(camelcase_str):
    """
    将驼峰命名转换为下划线命名
    :param camelcase_str: 驼峰命名的字符串，如 'helloWorld'
    :return: 下划线命名的字符串，如 'hello_world'
    """
    result = []
    for i, char in enumerate(camelcase_str):
        if char.isupper() and i > 0:
            result.append("_")
        result.append(char.lower())
    return "".join(result)


def rename_dict_key(data, rename_method):
    if isinstance(data, dict):
        new_dict = {}
        for key, value in data.items():
            new_key = rename_method(key)
            if isinstance(value, dict):
                new_dict[new_key] = rename_dict_key(value, rename_method)
            elif isinstance(value, list):
                new_list = []
                for item in value:
                    if isinstance(item, dict):
                        new_list.append(rename_dict_key(item, rename_method))
                    else:
                        new_list.append(item)
                new_dict[new_key] = new_list
            else:
                new_dict[new_key] = value
        return new_dict
    else:
        return data


# 测试代码
if __name__ == "__main__":
    # 下划线转驼峰测试
    print(underscore_to_camelcase("hello_world"))  # 输出: helloWorld
    print(underscore_to_camelcase("my_variable_name"))  # 输出: myVariableName

    # 驼峰转下划线测试
    print(camelcase_to_underscore("helloWorld"))  # 输出: hello_world
    print(camelcase_to_underscore("myVariableName"))  # 输出: my_variable_name

    # 双向转换测试
    original = "this_is_a_test"
    camel = underscore_to_camelcase(original)
    underscore = camelcase_to_underscore(camel)
    print(f"Original: {original}, Camel: {camel}, Back: {underscore}")
    # 输出: Original: this_is_a_test, Camel: thisIsATest, Back: this_is_a_test
