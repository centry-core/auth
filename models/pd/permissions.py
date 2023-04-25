from pydantic import BaseModel


class ModeRoles(BaseModel):
    system: bool = True
    admin: bool = True
    editor: bool = False
    viewer: bool = False


class RecommendedRoles(BaseModel):
    administration: ModeRoles = ModeRoles()
    developer: ModeRoles = ModeRoles()
    default: ModeRoles = ModeRoles()


class Permissions(BaseModel):
    permissions: list[str]
    recommended_roles: RecommendedRoles = RecommendedRoles()
