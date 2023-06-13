package com.netf.netflix.Controller;

import com.netf.netflix.Constant.VideoRole;
import com.netf.netflix.Dto.VideoFormDto;
import com.netf.netflix.Entity.Profile;
import com.netf.netflix.Entity.Video;
import com.netf.netflix.Entity.VideoImg;
import com.netf.netflix.Repository.ProfileRepository;
import com.netf.netflix.Repository.VideoImgRepository;
import com.netf.netflix.Repository.VideoRepository;
import com.netf.netflix.Service.ProfileService;
import com.netf.netflix.Service.VideoService;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import java.util.*;
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
@Log
public class VideoController {

    private final VideoService videoService;
    private final VideoImgRepository videoImgRepository;
    private final VideoRepository videoRepository;
    private final ProfileRepository profileRepository;
    private final ProfileService profileService;
//    private static final List<VideoImgDto> uploadedVideoList = new ArrayList<>();


    @GetMapping(value = "/video/new")
    public String videoForm(Model model) {
        model.addAttribute("videoFormDto", new VideoFormDto());
        return "videos/videoForm";
    }



    @PostMapping(value = "/video/new")
    public String videoCreateFrom(@Valid VideoFormDto videoFormDto, BindingResult bindingResult, Model model,
                                  @RequestParam("videoImgFile") MultipartFile videoImgFile,
                                  @RequestParam("videoFile") MultipartFile videoFile){

        if(bindingResult.hasErrors()){
            return "videos/videoForm";
        }
        try {
            videoService.saveVideo(videoFormDto, videoImgFile, videoFile);
        } catch (Exception e) {
            model.addAttribute("errorMessage","영상업로드중 문제가 발생하였습니다.");
            return "videos/videoForm";
        }
        return "videos/videoForm";
    }

    @GetMapping("/search/{profileId}")
    public String videoList(@PathVariable("profileId")Long profileId, Model model, String searchKeyword,HttpSession session) {
        session.setAttribute("profileNm",profileId);
        Profile profile = profileRepository.findById(profileId)
                .orElseThrow(() -> new RuntimeException("Profile not found"));
        Profile selectedProfile = profileRepository.findById(profileId).orElse(null);
        if (selectedProfile == null) {
            throw new RuntimeException("프로필을 찾을 수 없습니다.");
        }
        model.addAttribute("selectedProfile", selectedProfile);
        List<Profile> otherProfiles = profileRepository.findByMember(profile.getMember())
                .stream()
                .filter(p -> !p.getId().equals(profileId))
                .collect(Collectors.toList());
        model.addAttribute("otherProfiles", otherProfiles);

        String profileImageUrl = profile.getImageUrl();
        // 프로필 이미지 URL이 null인 경우 기본값을 설정합니다
        if (profileImageUrl == null) {
            profileImageUrl = "/images/default-profile-image.jpg";  // 기본 이미지 URL 설정
        }
        model.addAttribute("profileImageUrl", profileImageUrl);

        List<Video> list = null;
        List<VideoImg> videoImgs = videoImgRepository.findAll();
        model.addAttribute("videoImgs",videoImgs);

        if (searchKeyword == null) {
            list = null;
        } else {
            list = videoService.videoSearchList(searchKeyword);
        }

        model.addAttribute("list", list);
        model.addAttribute("uploadedVideoList", videoImgRepository.findAll()); // 이미지 정보 조회

        return "/rightmain/search";
    }

    @GetMapping("/drama/{profileId}")
    public String dramaList(@PathVariable("profileId") Long profileId, Model model, HttpSession session){

        session.setAttribute("profileNm",profileId);
        Profile profile = profileRepository.findById(profileId)
                .orElseThrow(() -> new RuntimeException("Profile not found"));
        Profile selectedProfile = profileRepository.findById(profileId).orElse(null);
        if (selectedProfile == null) {
            throw new RuntimeException("프로필을 찾을 수 없습니다.");
        }

        // 헤더이미지부르는부분
        model.addAttribute("selectedProfile", selectedProfile);
        List<Profile> otherProfiles = profileRepository.findByMember(profile.getMember())
                .stream()
                .filter(p -> !p.getId().equals(profileId))
                .collect(Collectors.toList());
        model.addAttribute("otherProfiles", otherProfiles);

        // favoriteVideos 값을 모델에 추가합니다
        model.addAttribute("favoriteVideos", profile.getFavoriteVideos());

        List<String> subjects = videoRepository.findAllGenres();
        List<Video> videos = videoRepository.findByVideoRole(VideoRole.DRAMA);

        for (Video video : videos) {
            System.out.println(video.getId()+video.getVideoNm()+video.getGenres()+video.getDescription());
        }

        if (!videos.isEmpty()) {
            // 랜덤한 인덱스를 생성
            int randomIndex = new Random().nextInt(videos.size());
            // 랜덤한 비디오 선택
            Video randomVideo = videos.get(randomIndex);
            // 선택한 비디오를 모델에 추가
            model.addAttribute("randomVideo", randomVideo);
        }


        model.addAttribute("subjects",subjects);
        model.addAttribute("videos",videos);
        //세션 + 하단 두줄 영화 및 mylist 추가
//        List<VideoImg> videoImgs = videoImgRepository.findAll();
//        model.addAttribute("videoImgs",videoImgs);
        String profileImageUrl = profile.getImageUrl();
        // 프로필 이미지 URL이 null인 경우 기본값을 설정합니다
        if (profileImageUrl == null) {
            profileImageUrl = "/images/default-profile-image.jpg";  // 기본 이미지 URL 설정
        }
        List<VideoImg> videoImgs = videoImgRepository.findAll();
        model.addAttribute("videoImgs",videoImgs);
        model.addAttribute("profileImageUrl", profileImageUrl);

        return "/leftmain/drama";
    }

    @GetMapping("/movie/{profileId}")
    public String movieList(@PathVariable("profileId")Long profileId, Model model,HttpSession session){

        session.getAttribute("profileNm");
        // 프로필 ID를 통해 프로필을 조회하고 favoriteVideos 값을 가져옵니다
        Profile profile = profileRepository.findById(profileId)
                .orElseThrow(() -> new RuntimeException("Profile not found"));

        Profile selectedProfile = profileRepository.findById(profileId).orElse(null);
        if (selectedProfile == null) {
            throw new RuntimeException("프로필을 찾을 수 없습니다.");
        }

        model.addAttribute("favoriteVideos", profile.getFavoriteVideos());

        model.addAttribute("selectedProfile", selectedProfile);
        List<Profile> otherProfiles = profileRepository.findByMember(profile.getMember())
                .stream()
                .filter(p -> !p.getId().equals(profileId))
                .collect(Collectors.toList());
        model.addAttribute("otherProfiles", otherProfiles);

        List<String> subjects = videoRepository.findAllGenres();
        List<Video> videos = videoRepository.findByVideoRole(VideoRole.MOVIE);

        for (Video video : videos) {
            System.out.println(video.getId()+video.getVideoNm()+video.getGenres()+video.getDescription());
        }

        if (!videos.isEmpty()) {
            // 랜덤한 인덱스를 생성
            int randomIndex = new Random().nextInt(videos.size());
            // 랜덤한 비디오 선택
            Video randomVideo = videos.get(randomIndex);
            // 선택한 비디오를 모델에 추가
            model.addAttribute("randomVideo", randomVideo);
        }

        String profileImageUrl = profile.getImageUrl();
        // 프로필 이미지 URL이 null인 경우 기본값을 설정합니다
        if (profileImageUrl == null) {
            profileImageUrl = "/images/default-profile-image.jpg";  // 기본 이미지 URL 설정
        }
        model.addAttribute("profileImageUrl", profileImageUrl);

        List<VideoImg> videoImgs = videoImgRepository.findAll();
        model.addAttribute("videoImgs",videoImgs);
        model.addAttribute("subjects",subjects);
        model.addAttribute("videos",videos);


        return "/leftmain/movie";
    }

    @GetMapping("/mylist/{profileId}")
    public String myList(@PathVariable("profileId")Long profileId, Model model,HttpSession session){

        session.getAttribute("profileNm");
        Profile profile = profileRepository.findById(profileId)
                .orElseThrow(() -> new RuntimeException("Profile not found"));
        Profile selectedProfile = profileRepository.findById(profileId).orElse(null);
        if (selectedProfile == null) {
            throw new RuntimeException("프로필을 찾을 수 없습니다.");
        }
        profileService.printFavoriteVideoIds(profileId);

        model.addAttribute("favoriteVideos", profile.getFavoriteVideos());

        model.addAttribute("selectedProfile", selectedProfile);
        List<Profile> otherProfiles = profileRepository.findByMember(profile.getMember())
                .stream()
                .filter(p -> !p.getId().equals(profileId))
                .collect(Collectors.toList());
        model.addAttribute("otherProfiles", otherProfiles);
        // 좋아하는 비디오 리스트 가져오기
        Set<Long> favoriteVideosId = profile.getFavoriteVideos();

        String profileImageUrl = profile.getImageUrl();
        // 프로필 이미지 URL이 null인 경우 기본값을 설정합니다
        if (profileImageUrl == null) {
            profileImageUrl = "/images/default-profile-image.jpg";  // 기본 이미지 URL 설정
        }
        List<VideoImg> videoImgs = videoImgRepository.findAll();
        model.addAttribute("videoImgs",videoImgs);
        model.addAttribute("profileImageUrl", profileImageUrl);
        List<Video> videos =videoRepository.findAllById(favoriteVideosId);
        // 모델에 좋아하는 비디오 리스트 추가
        model.addAttribute("videos", videos);
        return "/leftmain/mylist";
    }

    @GetMapping("/recent/{profileId}")
    public String recentView(@PathVariable("profileId")Long profileId ,Model model,HttpSession session){

        session.getAttribute("profileNm");
        Profile profile = profileRepository.findById(profileId)
                .orElseThrow(() -> new RuntimeException("Profile not found"));
        Profile selectedProfile = profileRepository.findById(profileId).orElse(null);
        if (selectedProfile == null) {
            throw new RuntimeException("프로필을 찾을 수 없습니다.");
        }
        profileService.printRecentlyViewedVideos(profileId);

        model.addAttribute("favoriteVideos", profile.getFavoriteVideos());
        model.addAttribute("selectedProfile", selectedProfile);
        List<Profile> otherProfiles = profileRepository.findByMember(profile.getMember())
                .stream()
                .filter(p -> !p.getId().equals(profileId))
                .collect(Collectors.toList());
        model.addAttribute("otherProfiles", otherProfiles);

        // 좋아하는 비디오 리스트 가져오기
        List<Long> recentViewId = profile.getRecentlyViewedVideos();
        List<Video> recentVideos = new ArrayList<>();
        List<VideoImg> videoImgs = videoImgRepository.findAll();
        model.addAttribute("videoImgs",videoImgs);

        for (Long videoId : recentViewId) {
            Video video = videoRepository.findById(videoId)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid video ID: " + videoId));
            recentVideos.add(video);
        }
        String profileImageUrl = profile.getImageUrl();
        // 프로필 이미지 URL이 null인 경우 기본값을 설정합니다
        if (profileImageUrl == null) {
            profileImageUrl = "/images/default-profile-image.jpg";  // 기본 이미지 URL 설정
        }
        model.addAttribute("profileImageUrl", profileImageUrl);


// 모델에 좋아하는 비디오 리스트 추가o
        model.addAttribute("recentVideos", recentVideos);
        return "/leftmain/recent";
    }

}
