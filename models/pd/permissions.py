from pydantic import BaseModel


class ModeRoles(BaseModel):
    admin: bool = True
    editor: bool = True
    viewer: bool = True


class RecommendedRoles(BaseModel):
    administration: ModeRoles = ModeRoles()
    project: ModeRoles = ModeRoles()
    develop: ModeRoles = ModeRoles()


class Permissions(BaseModel):
    permissions: list[str]
    recommended_roles: RecommendedRoles = RecommendedRoles()

