package com.netf.netflix.Controller;

import com.netf.netflix.Constant.Role;
import com.netf.netflix.Entity.Member;
import com.netf.netflix.Entity.Profile;
import com.netf.netflix.Entity.Video;
import com.netf.netflix.Entity.VideoImg;
import com.netf.netflix.Repository.MemberRepository;
import com.netf.netflix.Repository.ProfileRepository;
import com.netf.netflix.Repository.VideoImgRepository;
import com.netf.netflix.Repository.VideoRepository;
import com.netf.netflix.Service.MemberService;
import com.netf.netflix.Service.ProfileService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
public class HomeController {

    private final MemberService memberService;
    private final ProfileRepository profileRepository;
    private final MemberRepository memberRepository;
    private final VideoImgRepository videoImgRepository;
    private final VideoRepository videoRepository;

    @GetMapping("/")
    public String home(Model model, Principal principal) {
        // 로그인된 멤버의 정보 가져오기
        String email = principal.getName();
        Member member = memberService.findMemberByEmail(email);

        // 멤버의 프로필 리스트 가져오기
        List<Profile> profiles = profileRepository.findByMember(member);

        // 프로필 이름 리스트 가져오기
        List<String> profileNames = profiles.stream()
                .map(Profile::getName)
                .collect(Collectors.toList());

        // 첫 번째 프로필을 선택된 프로필로 설정
        Profile selectedProfile = profiles.get(0);
        model.addAttribute("selectedProfile", selectedProfile);

        // 나머지 프로필 정보를 가져와서 모델에 추가
        List<Profile> otherProfiles = profiles.stream()
                .filter(profile -> !profile.getId().equals(selectedProfile.getId()))
                .collect(Collectors.toList());
        model.addAttribute("otherProfiles", otherProfiles);

        List<VideoImg> videoImgs = videoImgRepository.findAll();
        model.addAttribute("videoImgs",videoImgs);

        //비디오 부분
        /// 비디오 내용 홈와면의 비디오 내용 필요한것 : 랜덤/ 최근 / 새로 올라운 콘텐츠 / top10
//       프로파일 이미지는 이미 있기 때문에 세션으로 가져올 필요없다
//        Long profileId = (Long) session.getAttribute("profileNm");
//        Profile profile = profileRepository.findById(profileId)
//                .orElseThrow(() -> new RuntimeException("Profile not found"));
        // 랜덤 부분
        List<Video> videos = videoRepository.findAll();
        List<Video> randomVideos = new ArrayList<>();
        Set<Integer> chosenIndexes = new HashSet<>();

        while (randomVideos.size() < 4 && chosenIndexes.size() < videos.size()) {
            int randomIndex = new Random().nextInt(videos.size());
            if (chosenIndexes.contains(randomIndex)) {
                continue; // 이미 선택된 인덱스는 건너뛰기
            }
            chosenIndexes.add(randomIndex);
            Video randomVideo = videos.get(randomIndex);
            randomVideos.add(randomVideo);
        }

        model.addAttribute("randomVideo2", randomVideos);
        if (!randomVideos.isEmpty()) {
            model.addAttribute("randomVideo", randomVideos.get(0));
        }


        //최근본
        List<Long> recentViewId =  selectedProfile.getRecentlyViewedVideos();
        List<Video> recentVideos = new ArrayList<>();

        for (Long videoId : recentViewId) {
            Video video = videoRepository.findById(videoId)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid video ID: " + videoId));
            recentVideos.add(video);
        }

        model.addAttribute("recentVideos", recentVideos);

        // 찜목록
        model.addAttribute("favoriteVideos", selectedProfile.getFavoriteVideos());

        // 좋아하는 비디오 리스트 가져오기
        Set<Long> favoriteVideosId = selectedProfile.getFavoriteVideos();

        List<Video> like_videos =videoRepository.findAllById(favoriteVideosId);
        // 모델에 좋아하는 비디오 리스트 추가
        model.addAttribute("like_videos",like_videos);

//        업데이트 비디오는 프로파일넘버가 필요없다
        List<Video> uploadVideos = videoRepository.findDistinctByOrderByVideoImgUploadDateDesc();
        if(uploadVideos!=null){
            model.addAttribute("uploadVideos",uploadVideos );
        }else{
            System.out.println("null입니다");
        }

        List<Video> top10Videos = videoRepository.findTop10ByOrderByViewCountDesc();
        model.addAttribute("top10Videos", top10Videos);

        // Get the role of the user
//            Role role = member.getRole();
//
//        model.addAttribute("role", role);


        return "home";
    }

}
