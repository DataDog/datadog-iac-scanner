from pydantic import BaseModel


class QueryAndDescriptionOutput(BaseModel):
    queryName: str
    descriptionText: str

    def toDict(self):
        return self.model_dump()


class DescriptionOutput(BaseModel):
    descriptionText: str

    def toDict(self):
        return self.model_dump()
