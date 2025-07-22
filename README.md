
id: social-links-detected

info:
  name: Social Media Links Detector
  author: adham-heinrich
  severity: info
  description: Detects presence of social media profile links
  tags: exposure, fingerprint, social, passive

requests:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers-condition: or
    matchers:
      - type: regex
        name: instagram
        regex:
          - "instagram\\.com\\/[a-zA-Z0-9_.]+"

      - type: regex
        name: facebook
        regex:
          - "facebook\\.com\\/[a-zA-Z0-9.]+"

      - type: regex
        name: twitter
        regex:
          - "(twitter\\.com|x\\.com)\\/[a-zA-Z0-9_]+"

      - type: regex
        name: tiktok
        regex:
          - "tiktok\\.com\\/@[a-zA-Z0-9_.]+"

      - type: regex
        name: youtube
        regex:
          - "youtube\\.com\\/(channel|user|c)\\/[a-zA-Z0-9_-]+"

