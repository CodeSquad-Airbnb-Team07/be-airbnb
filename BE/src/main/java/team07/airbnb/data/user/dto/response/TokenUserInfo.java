package team07.airbnb.data.user.dto.response;

import team07.airbnb.data.user.enums.Role;
import team07.airbnb.entity.UserEntity;

public record TokenUserInfo(Long id, String name, String profileImg, Role role) {

    public static TokenUserInfo of(UserEntity userEntity) {
        return new TokenUserInfo(userEntity.getId(), userEntity.getName(), userEntity.getPicture(), userEntity.getRole());
    }

    public String stringRole() {
        return this.role.getKey();
    }

    public UserEntity toUserEntity() {
        return new UserEntity(
                this.id,
                this.name,
                this.profileImg,
                this.role
        );
    }
}
