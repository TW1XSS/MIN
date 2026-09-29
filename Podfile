# MIN — Tor (C Tor) + IPtProxy (PT: obfs4/snowflake/webtunnel/dnstt).
# Клиент iOS: C Tor + IPtProxy работают внутри приложения, без VPN-профиля.
platform :ios, '15.0'

target 'MIN' do
  use_frameworks!

  # C Tor (iCepa): прекомпилированные xcframework, API TORThread/TORController.
  pod 'Tor', '~> 409'

  # PT для iOS: obfs4 (Lyrebird) + snowflake + webtunnel + dnstt.
  pod 'IPtProxy', '~> 5.5'

  # Юнит-таргету нужны search paths модулей (иначе Swift не резолвит Tor/IPtProxy).
  target 'MINTests' do
    inherit! :search_paths
  end
end
