import subprocess


def powershell_command():
    # 定义PowerShell命令
    ps_command = 'powershell -ExecutionPolicy bypass -File baseline/windows.ps1'
    # 使用subprocess.run来运行PowerShell命令
    result = subprocess.run(['powershell', '-Command', ps_command],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # 打印输出和错误信息
    print(result.stdout)  # 输出信息
    print(result.stderr)  # 错误信息
    #保存输出，转成utf-8编码
    output = result.stdout.encode('utf-8')
    with open('output.txt', 'wb') as f:
        f.write(output)
