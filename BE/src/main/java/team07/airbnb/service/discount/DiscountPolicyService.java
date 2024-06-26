package team07.airbnb.service.discount;

import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Service;
import team07.airbnb.data.discount.beans.DiscountPolicy;
import team07.airbnb.entity.DiscountPolicyEntity;
import team07.airbnb.exception.not_found.DiscountPolicyNotFoundException;
import team07.airbnb.repository.DiscountPolicyRepository;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class DiscountPolicyService {

    private final DiscountPolicyRepository discountPolicyRepository;
    private final ApplicationContext ac;

    public int getDiscountPrice(int roughPrice) {
        //일단 주단위 할인
        Optional<DiscountPolicyEntity> weekDiscount = discountPolicyRepository.findByDescription("주단위할인");
        DiscountPolicyEntity entity = weekDiscount.orElseThrow(DiscountPolicyNotFoundException::new);

        String policyBeanName = entity.getPolicyBeanName();
        DiscountPolicy bean = (DiscountPolicy) ac.getBean(policyBeanName);

        return bean.getDiscountPrice(roughPrice);
    }
}
