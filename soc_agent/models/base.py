from dataclasses import asdict, dataclass


@dataclass(slots=True)
class BaseModel:
    def to_dict(self):
        return asdict(self)
