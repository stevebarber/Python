# Log filename
LOG_FILE = 'logfile'
# Device group to run script against
DEVICE_GROUP = '<device_group>'
# Tag cloned and original rule with the following tag
RULE_TAG = 'ZONE_SPLIT'
# Cloned rules will maintain original rule name with the following suffix.
# Final rule name will have an incrementing integer added (e.g. 'my_rule_clone_01')
RULE_SUFFIX = '_clone_'
# Split disabled rules
SPLIT_DISABLED = False
# Ignore rules with specific tag in comma-separated list (e.g. IGNORE_TAG = ['TAG1', 'TAG2', 'TAG3'] )
IGNORE_TAG = ['tag1', 'tag2']