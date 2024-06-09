package team07.airbnb.domain.booking;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import team07.airbnb.domain.booking.entity.BookingEntity;
import team07.airbnb.domain.user.entity.UserEntity;

import java.util.List;

@Repository
public interface BookingRepository extends JpaRepository<BookingEntity, Long> {
    List<BookingEntity> findAllByHost(UserEntity host);

    boolean existsByIdAndBooker(Long bookingId, UserEntity booker);

    boolean existsByIdAndHost(Long bookingId, UserEntity host);
}
