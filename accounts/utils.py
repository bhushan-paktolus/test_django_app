import subprocess

def display_otp_in_terminal(email, otp):
    """Display OTP prominently in Windows PowerShell terminal"""
    powershell_command = f'''
    Write-Host "`n`n"
    Write-Host ("=" * 70) -ForegroundColor Yellow
    Write-Host "`n   PASSWORD RESET OTP DETAILS" -ForegroundColor Green
    Write-Host "`n   Email:" -NoNewline
    Write-Host " {email}" -ForegroundColor Cyan
    Write-Host "`n   OTP:" -NoNewline
    Write-Host " {otp}" -ForegroundColor Red
    Write-Host "`n   Please use this OTP to reset your password"
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Yellow
    Write-Host "`n"
    '''
    
    subprocess.run(['powershell', '-Command', powershell_command], shell=True) 