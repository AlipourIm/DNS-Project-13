import Resources


class Message:

    source_rsa_pk: str # for undeniability

    def __init__(self, message_type: str, source_username, target_username, seq, signature, text):
        self.message_type = message_type
        self.source_username = source_username
        self.target_username = target_username
        self.seq = seq
        self.signature = signature
        self.text = text

    def __str__(self):
        return f"{self.message_type}{Resources.SEP}" \
               f"{self.source_username}{Resources.SEP}" \
               f"{self.target_username}{Resources.SEP}" \
               f"{self.seq}{Resources.SEP}" \
               f"{self.signature}{Resources.SEP}" \
               f"{self.text}"

    def set_source_rsa_pk(self, source_rsa_pk):
        self.source_rsa_pk = source_rsa_pk

