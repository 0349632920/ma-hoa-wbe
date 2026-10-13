# truyen_utils.py — Truyện mẫu fallback (khi AI lỗi)
import random

# ═══════════════════════════════════════════════
# TRUYỆN MẪU — 10 THỂ LOẠI
# ═══════════════════════════════════════════════

STORIES = {
    'boylove': [
        """Minh và Hùng học cùng lớp 12A3. Minh là lớp trưởng nghiêm túc, Hùng là cậu học sinh cá biệt hay ngủ gật trong giờ.

Một hôm, Minh được phân công kèm Hùng học Toán. Ban đầu Hùng tỏ ra khó chịu, nhưng dần dần cậu nhận ra Minh không chỉ giỏi mà còn rất kiên nhẫn.

"Mày kiên nhẫn với tao thật đấy." — Hùng nói, mắt nhìn Minh.

Minh đỏ mặt: "Vì... tao không muốn mày trượt tốt nghiệp."

Đêm hôm đó, Hùng thức khuya làm bài tập. Sáng hôm sau, cậu đến lớp sớm, đặt lên bàn Minh một ly cà phê sữa và mẩu giấy: "Cảm ơn mày. Tao sẽ cố gắng."

Minh đọc mẩu giấy, tim đập nhanh hơn bình thường. Cậu không hiểu tại sao.

Rồi những buổi học thêm, những lần đi ăn chung, những tin nhắn đến khuya... Cả hai dần nhận ra tình cảm của mình dành cho đối phương không chỉ là bạn bè.

Ngày tốt nghiệp, Hùng nắm tay Minh: "Tao đậu rồi. Nhờ mày cả."

Minh cười, mắt rưng rưng: "Vậy... mình đi tiếp con đường phía trước nhé?"

Hùng siết chặt tay Minh: "Ừ. Cùng nhau."

**Bài học**: Tình yêu chân thành bắt đầu từ sự quan tâm và kiên nhẫn.""",
    ],
    'girllove': [
        """Lan và Mai là bạn thân từ nhỏ. Lan dịu dàng, thích vẽ. Mai mạnh mẽ, thích võ thuật.

Một hôm, Mai bị thương khi tập võ. Lan ngồi bên cạnh, băng bó vết thương cho cô.

"Đau không?" — Lan hỏi, giọng lo lắng.

Mai cười: "Không đau. Vì có mày ở đây."

Lan ngẩng lên, bắt gặp ánh mắt của Mai. Cả hai im lặng vài giây. Rồi Lan đỏ mặt, cúi xuống tiếp tục băng bó.

Từ hôm đó, Lan nhận ra mình hay nhìn Mai hơn. Mai cũng vậy.

Ngày sinh nhật Lan, Mai tặng cô một bức tranh — chính Mai tự vẽ, dù tay cô chưa từng cầm cọ.

"Tao vẽ xấu lắm, nhưng tao muốn tặng mày." — Mai nói, mặt đỏ.

Lan nhìn bức tranh — hai cô gái nắm tay nhau dưới nắng vàng. Nước mắt Lan lăn dài: "Đẹp lắm. Tao sẽ giữ mãi."

Mai nắm tay Lan: "Vậy... mình nắm tay nhau mãi nhé?"

Lan gật đầu, cười trong nước mắt: "Ừ."

**Bài học**: Tình bạn có thể chuyển thành tình yêu, nếu cả hai đủ dũng cảm.""",
    ],
    'tinh_cam': [
        """Anh và em gặp nhau ở quán cà phê nhỏ cuối phố. Anh là nhạc sĩ nghèo, em là cô giáo dạy văn.

Em ngồi bàn cạnh cửa sổ, chăm chú đọc sách. Anh ngồi đối diện, gảy đàn guitar. Bài hát anh viết dở dang — chưa có lời.

"Anh đang viết gì vậy?" — em hỏi, mắt không rời khỏi trang sách.

"Tình ca. Nhưng chưa biết viết về ai."

Em ngẩng lên, cười: "Vậy viết về em đi. Em tên Hạ."

Từ hôm đó, quán cà phê có thêm một vị khách quen. Mỗi chiều, anh đàn, em đọc.

Ba tháng sau, anh hoàn thành bài hát. Anh đặt tên nó là "Hạ".

"Em ơi, bài hát này anh viết tặng em. Nhưng anh chẳng có gì ngoài cây đàn này. Em có chấp nhận làm vợ anh không?"

Em nắm tay anh: "Em chấp nhận. Vì anh có trái tim biết yêu."

**Bài học**: Tình yêu đích thực không cần vật chất, chỉ cần một trái tim chân thành.""",
    ],
    'vo_hiep': [
        """Trên đỉnh Thiên Sơn, hai kiếm khách đối mặt. Một là Lý Phong — kiếm khách trẻ tuổi, nổi danh giang hồ. Một là Âu Dương Hàn — đại sư huynh của Võ Đang phái.

"Lý huynh, ngươi đến đây để tỷ thí hay để cầu học?" — Âu Dương Hàn hỏi.

Lý Phong chắp tay: "Tại hạ đến để thỉnh giáo."

Hai người rút kiếm. Gió nổi, mây cuộn. Ba mươi chiêu qua đi, bất phân thắng bại. Đến chiêu thứ ba mươi mốt, Lý Phong dùng chiêu "Phá Vân Kiếm" — chiêu thức gia truyền.

Âu Dương Hàn đỡ không kịp, lùi ba bước. Nhưng Lý Phong cũng dừng lại, không truy kích.

"Tại sao ngươi dừng?" — Âu Dương Hàn hỏi.

"Vì tại hạ biết, tỷ thí không phải để thắng. Mà để học hỏi." — Lý Phong đáp.

Âu Dương Hàn cười lớn: "Hay lắm! Ngươi là người đầu tiên hiểu được đạo kiếm. Từ nay, ta nhận ngươi làm đệ tử."

Hai người cùng xuống núi, kết nghĩa huynh đệ. Từ đó, giang hồ có thêm một cặp kiếm khách nổi danh.

**Bài học**: Kẻ mạnh thật sự là kẻ biết dừng đúng lúc.""",
    ],
    'co_dai': [
        """Trong cung điện nguy nga, công chúa Linh Nhi đang ngồi bên cửa sổ, mắt hướng về phía xa xăm.

Nàng là con gái duy nhất của hoàng đế, nhưng nàng không muốn sống trong cung. Nàng muốn ra ngoài, muốn tự do.

Một hôm, nàng cải trang thành thường dân, trốn khỏi cung. Nàng gặp một chàng thư sinh nghèo tên là Trần Văn. Chàng đang ngồi đọc sách bên bờ sông.

"Cô nương, sao lại đi một mình nơi đây?" — chàng hỏi.

"Ta... ta muốn ngắm cảnh." — nàng đáp.

Hai người trò chuyện rất lâu. Chàng kể về ước mơ thi đỗ trạng nguyên. Nàng kể về ước mơ tự do.

"Vậy chúng ta có cùng ước mơ rồi." — chàng cười.

Nhưng rồi quân lính tìm thấy nàng. Nàng phải trở về cung. Trước khi đi, nàng trao cho chàng một chiếc khăn tay thêu hình đôi chim uyên ương.

"Chờ ta. Ta sẽ trở lại." — nàng nói.

Ba năm sau, chàng thi đỗ trạng nguyên. Ngày vinh quy bái tổ, chàng xin hoàng đế cho cưới công chúa.

Hoàng đế nhìn chàng: "Ngươi dám ước mơ lớn đấy."

Chàng đáp: "Vì ước mơ của thần... cũng là ước mơ của công chúa."

**Bài học**: Tình yêu có thể vượt qua mọi rào cản, nếu đủ kiên nhẫn và dũng cảm.""",
    ],
    'hoc_duong': [
        """Nam và Linh là đôi bạn thân từ lớp 6. Nam học giỏi Toán, Linh học giỏi Văn. Họ bổ trợ cho nhau.

Lớp 12, cả hai cùng ôn thi đại học. Nam mơ ước vào Bách Khoa, Linh mơ ước vào Sư Phạm. Hai ngôi trường ở hai đầu thành phố.

"Vậy là mình không học chung nữa rồi." — Linh nói, mắt buồn.

Nam im lặng một lúc, rồi nói: "Không sao. Mình sẽ cùng nhau cố gắng. Học xong, mình vẫn là bạn."

Linh cười: "Ừ. Bạn thân."

Ngày thi tốt nghiệp, cả hai đều làm bài tốt. Ngày nhận kết quả, Nam đỗ Bách Khoa, Linh đỗ Sư Phạm.

Linh ôm Nam: "Chúc mừng cậu!"

Nam cười: "Chúc mừng cậu nữa."

Ngày chia tay, cả hai hẹn gặp lại sau 4 năm. Linh tặng Nam một cuốn sổ — trong đó có những dòng nhật ký cô viết về cậu.

Nam đọc, mắt rưng rưng: "Tớ... tớ cũng thích cậu."

Linh đỏ mặt: "Vậy... hẹn gặp lại sau 4 năm nhé?"

Nam gật đầu: "Hẹn gặp lại."

**Bài học**: Tình bạn đẹp có thể trở thành tình yêu, nếu cả hai cùng chờ đợi.""",
    ],
    'huyen_huyen': [
        """Lâm Thanh là một tu sĩ trẻ tuổi, tu luyện ở Thanh Vân Tông. Hắn có linh căn kém, tu luyện 10 năm vẫn ở Trúc Cơ kỳ.

Một hôm, hắn tình cờ nhặt được một viên đá lạ. Viên đá phát sáng, và một giọng nói vang lên trong đầu hắn: "Ta là Long Hồn. Ngươi có muốn trở thành cường giả không?"

Lâm Thanh giật mình: "Ngươi là ai?"

"Ta là linh hồn của một con rồng cổ đại. Ta sẽ giúp ngươi tu luyện, đổi lại ngươi phải giúp ta tìm lại thân xác."

Lâm Thanh đồng ý. Từ đó, hắn tu luyện thần tốc. Chỉ 3 năm, hắn đã đạt Kim Đan kỳ. 10 năm sau, hắn đạt Nguyên Anh kỳ — cảnh giới mà nhiều tu sĩ mất cả đời không đạt được.

Nhưng rồi hắn nhận ra, Long Hồn không phải là bạn. Đó là một tồn tại nguy hiểm, đang lợi dụng hắn để hồi sinh.

Lâm Thanh quyết định phản kháng. Hắn dùng tất cả tu vi để phong ấn Long Hồn.

"Ngươi sẽ hối hận!" — Long Hồn gào thét.

"Ta không hối hận. Vì ta là Lâm Thanh — không phải công cụ của ai."

Sau khi phong ấn Long Hồn, Lâm Thanh mất hết tu vi. Nhưng hắn không hối hận. Vì hắn đã giữ được linh hồn của mình.

**Bài học**: Sức mạnh thật sự không đến từ người khác, mà từ chính bản thân.""",
    ],
    'kinh_di': [
        """11 giờ đêm. Bệnh viện vắng lặng. Bác sĩ Nam trực ca đêm.

Đèn phòng cấp cứu bỗng nhấp nháy. Tiếng cười trẻ con vang lên từ hành lang — nhưng không có ai.

Nam bước ra kiểm tra. Cửa phòng 302 mở toang. Trong phòng, một cô bé mặc áo trắng đang ngồi quay mặt vào tường.

"Cháu gái, giờ này sao chưa ngủ?"

Cô bé từ từ quay lại. Mặt cô bé trắng bệch, mắt đen láy nhìn thẳng vào Nam.

"Bác sĩ ơi... cháu muốn về nhà."

Nam lùi lại một bước. Anh nhớ ra — phòng 302 đã bỏ trống từ 5 năm trước. Cô bé từng nằm đó chết vì bệnh hiểm nghèo.

"Cháu muốn về nhà ở đâu?"

"Về với mẹ. Mẹ cháu ở quê."

Nam gọi điện cho mẹ cô bé. Bà đến ngay trong đêm. Khi bà bước vào phòng, cô bé mỉm cười, rồi từ từ tan biến.

Sáng hôm sau, Nam đến thăm mộ cô bé. Trên bia mộ ghi: "Mong con được về nhà."

**Bài học**: Đôi khi, điều người đã khuất cần nhất chỉ là được về nhà.""",
    ],
    'hai_huoc': [
        """Nam là sinh viên năm 3, chuyên gia "trốn học". Cậu nổi tiếng khắp khoa vì... điểm danh chưa bao giờ đủ.

Một hôm, Nam quyết định đi học. Cậu vào lớp, ngồi cuối, hi vọng không ai nhận ra.

Cô giáo điểm danh: "Nguyễn Văn Nam?"

Nam giơ tay: "Dạ có!"

Cô giáo: "Ồ, Nam đây à? Hôm nay trời đẹp quá nhỉ?"

Nam: "Dạ vâng ạ!"

Cô: "Vậy mà Nam không ở nhà ngủ cho khỏe, lên lớp làm gì?"

Cả lớp cười ồ. Nam đỏ mặt: "Dạ... con muốn học ạ!"

Cô: "Tốt! Vậy Nam cho cô biết, bài giảng hôm qua cô dạy gì?"

Nam: "Dạ... con không biết ạ!"

Cô: "Vậy mà bảo muốn học. Thôi, Nam ra ngoài đứng cho cô!"

Nam: "Dạ vâng ạ!"

Nam bước ra. Đứng ngoài hành lang, cậu bỗng nghe cô giáo nói vọng ra: "Nam ơi, hôm nay lớp học online. Em vào Zoom đi!"

Nam: "Ơ... nhưng con đang ở trường mà cô?"

Cô: "Ừ, cô cũng ở nhà. Cô quên báo!"

**Bài học**: Đôi khi, "trốn học" lại là lựa chọn... đúng đắn!""",
    ],
    'scifi': [
        """Năm 2157, Trái Đất đã cạn kiệt tài nguyên. Nhân loại di cư lên sao Hỏa.

Kỹ sư Minh là một trong 200 người cuối cùng ở lại Trạm Alpha để hoàn tất việc di tản. Nhưng một vụ nổ đã phá hủy hệ thống liên lạc. Minh bị mắc kẹt một mình.

Ngày 1: Minh kiểm tra hệ thống. Pin còn 15%. Oxy còn 72 giờ.

Ngày 3: Minh phát hiện một tín hiệu lạ từ phía Nam trạm. Có ai đó ngoài kia.

Ngày 7: Minh quyết định rời khỏi trạm, mang theo 30 giờ oxy. Cậu đi về phía tín hiệu.

Sau 12 giờ băng qua sa mạc đỏ, Minh tìm thấy một trạm cũ. Trong đó, một người phụ nữ Nga tên là Anya, cũng bị mắc kẹt 2 năm nay.

"Anh là người đầu tiên tôi gặp sau 2 năm." — Anya nói, nước mắt lăn dài.

Họ cùng nhau sửa hệ thống liên lạc. Sau 6 ngày, họ phát được tín hiệu SOS đến sao Hỏa.

Ngày 45: Tàu cứu hộ đến. Cả hai được đưa về sao Hỏa an toàn.

**Bài học**: Trong vũ trụ bao la, con người vẫn cần con người.""",
    ],
}


def get_truyen_fallback(the_loai='boylove'):
    """Lấy truyện mẫu theo thể loại (fallback)."""
    if the_loai not in STORIES:
        the_loai = 'boylove'

    return {
        'the_loai': the_loai,
        'truyen': random.choice(STORIES[the_loai]),
        'loai': 'local',
    }
